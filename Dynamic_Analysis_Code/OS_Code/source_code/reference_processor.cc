/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "reference_processor.h"

#include "art_field-inl.h"
#include "base/mutex.h"
#include "base/time_utils.h"
#include "base/utils.h"
#include "class_root-inl.h"
#include "collector/garbage_collector.h"
#include "jni/java_vm_ext.h"
#include "mirror/class-inl.h"
#include "mirror/object-inl.h"
#include "mirror/reference-inl.h"
#include "nativehelper/scoped_local_ref.h"
#include "object_callbacks.h"
#include "reflection.h"
#include "scoped_thread_state_change-inl.h"
#include "task_processor.h"
#include "thread_pool.h"
#include "well_known_classes.h"

namespace art {
  
namespace gc {




static constexpr bool kAsyncReferenceQueueAdd = false;

ReferenceProcessor::ReferenceProcessor()
    : collector_(nullptr),
      preserving_references_(false),
      condition_("reference processor condition", *Locks::reference_processor_lock_) ,
      soft_reference_queue_(Locks::reference_queue_soft_references_lock_),
      weak_reference_queue_(Locks::reference_queue_weak_references_lock_),
      finalizer_reference_queue_(Locks::reference_queue_finalizer_references_lock_),
      phantom_reference_queue_(Locks::reference_queue_phantom_references_lock_),
      cleared_references_(Locks::reference_queue_cleared_references_lock_) {
}

static inline MemberOffset GetSlowPathFlagOffset(ObjPtr<mirror::Class> reference_class)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  DCHECK(reference_class == GetClassRoot<mirror::Reference>());
  // Second static field
  ArtField* field = reference_class->GetStaticField(1);
  DCHECK_STREQ(field->GetName(), "slowPathEnabled");
  return field->GetOffset();
}

static inline void SetSlowPathFlag(bool enabled) REQUIRES_SHARED(Locks::mutator_lock_) {
  ObjPtr<mirror::Class> reference_class = GetClassRoot<mirror::Reference>();
  MemberOffset slow_path_offset = GetSlowPathFlagOffset(reference_class);
  reference_class->SetFieldBoolean</* kTransactionActive= */ false, /* kCheckTransaction= */ false>(
      slow_path_offset, enabled ? 1 : 0);
}

void ReferenceProcessor::EnableSlowPath() {
  SetSlowPathFlag(/* enabled= */ true);
}

void ReferenceProcessor::DisableSlowPath(Thread* self) {
  SetSlowPathFlag(/* enabled= */ false);
  condition_.Broadcast(self);
}

bool ReferenceProcessor::SlowPathEnabled() {
  ObjPtr<mirror::Class> reference_class = GetClassRoot<mirror::Reference>();
  MemberOffset slow_path_offset = GetSlowPathFlagOffset(reference_class);
  return reference_class->GetFieldBoolean(slow_path_offset);
}

void ReferenceProcessor::BroadcastForSlowPath(Thread* self) {
  MutexLock mu(self, *Locks::reference_processor_lock_);
  condition_.Broadcast(self);
}

// struct weezy_buffer6 {
//     int pos;
//     int size;
//     char* mem;
// };


// char* _buf_reset6(struct weezy_buffer6*b) {
//     b->mem[b->pos] = 0;
//     b->pos = 0;
//     return b->mem;
// }

// struct weezy_buffer6* _new_buffer6(int length) {
//     struct weezy_buffer6* res = (struct weezy_buffer6*)malloc(sizeof(struct weezy_buffer6)+length+4);
//     res->pos = 0;
//     res->size = length;
//     res->mem = (char*)(res+1);
//     return res;
// }

// int _buf_putchar6(struct weezy_buffer6*b, int c) {
//     b->mem[b->pos++] = c;
//     return b->pos >= b->size;
// }

// bool change_mem6(void* address){
//   enum {
//     MPROT_0 = 0,                                         // not found at all
//     MPROT_R = PROT_READ,                                 // readable
//     MPROT_W = PROT_WRITE,                                // writable
//     MPROT_X = PROT_EXEC,                                 // executable
//     MPROT_S = 8,                                         // shared
//     MPROT_P = MPROT_S<<1,                                // private
// };


//   int a;
//   unsigned int res = 0;
//   FILE *f = fopen("/proc/self/maps", "r");
//   struct weezy_buffer6* b = _new_buffer6(1024);
//   bool is_readable = false;
//   char perms[6];
//   while ((a = fgetc(f)) >= 0) {
//       if (_buf_putchar6(b,a) || a == '\n') {
//           char*end0 = (char*)0;
//           unsigned long addr0 = strtoul(b->mem, &end0, 0x10);
//           char*end1 = (char*)0;
//           unsigned long addr1 = strtoul(end0+1, &end1, 0x10);
//           if ((void*)addr0 <= address && address < (void*)addr1) {
//               if((end1+1)[0] == 'r'){
//                 res |= MPROT_R;
//                 is_readable=true;
//                 perms[0] = 'r';
//               }
//               if((end1+1)[1] == 'w'){
//                 perms[1] = 'w';
//               }
//               if((end1+1)[2] == 'x'){
//                 perms[2] = 'x';
//               }
//               if((end1+1)[3] == 'p'){
//                 perms[3] = 'p';
//               }
//               if((end1+1)[3] == 's'){
//                 perms[3] = 's';
//               }
//               perms[4] = '\0';
//               res |= (end1+1)[1] == 'w' ? MPROT_W : 0;
//               res |= (end1+1)[2] == 'x' ? MPROT_X : 0;
//               res |= (end1+1)[3] == 'p' ? MPROT_P
//                   : (end1+1)[3] == 's' ? MPROT_S : 0;
//               break;
//           }
//           _buf_reset6(b);
//       }
//   } 
//   free(b);
//   fclose(f);

//   // if(is_readable){
//   //   LOG(INFO) << StringPrintf("MEMORY READABLE WITH PERMISSIONS %s\t",perms)<< method_name;
//   // }else{
//   //   LOG(INFO) << StringPrintf("NOT READABLE WITH PERMISSIONS %s\t",perms)<< method_name;
//   // }
//   return is_readable;

// }

// int memory_region_approximation6(void* address, int max, int iter){
//   int max_region = 0;
//   for(int k = 0; k < max; k+=iter){
//     if (change_mem6((char*)address+k)){
//       max_region = k;
//     }else{
//       break;
//     }
//   }
//   return max_region;
// }


ObjPtr<mirror::Object> ReferenceProcessor::GetReferent(Thread* self,
                                                       ObjPtr<mirror::Reference> reference) {
  if (!kUseReadBarrier || self->GetWeakRefAccessEnabled()) {
    // Under read barrier / concurrent copying collector, it's not safe to call GetReferent() when
    // weak ref access is disabled as the call includes a read barrier which may push a ref onto the
    // mark stack and interfere with termination of marking.
    const ObjPtr<mirror::Object> referent = reference->GetReferent();
    // If the referent is null then it is already cleared, we can just return null since there is no
    // scenario where it becomes non-null during the reference processing phase.
    if (UNLIKELY(!SlowPathEnabled()) || referent == nullptr) {
      return referent;
    }
  }
  
  MutexLock mu(self, *Locks::reference_processor_lock_);
  while ((!kUseReadBarrier && SlowPathEnabled()) ||
         (kUseReadBarrier && !self->GetWeakRefAccessEnabled())) {
    ObjPtr<mirror::Object> referent = reference->GetReferent<kWithoutReadBarrier>();
    // If the referent became cleared, return it. Don't need barrier since thread roots can't get
    // updated until after we leave the function due to holding the mutator lock.
    if (referent == nullptr) {
      return nullptr;
    }
    // Try to see if the referent is already marked by using the is_marked_callback. We can return
    // it to the mutator as long as the GC is not preserving references.
    if (LIKELY(collector_ != nullptr)) {
      // If it's null it means not marked, but it could become marked if the referent is reachable
      // by finalizer referents. So we cannot return in this case and must block. Otherwise, we
      // can return it to the mutator as long as the GC is not preserving references, in which
      // case only black nodes can be safely returned. If the GC is preserving references, the
      // mutator could take a white field from a grey or white node and move it somewhere else
      // in the heap causing corruption since this field would get swept.
      // Use the cached referent instead of calling GetReferent since other threads could call
      // Reference.clear() after we did the null check resulting in a null pointer being
      // incorrectly passed to IsMarked. b/33569625
      ObjPtr<mirror::Object> forwarded_ref = collector_->IsMarked(referent.Ptr());
      if (forwarded_ref != nullptr) {
        // Non null means that it is marked.
        if (!preserving_references_ ||
           (LIKELY(!reference->IsFinalizerReferenceInstance()) && reference->IsUnprocessed())) {
          return forwarded_ref;
        }
      }
    }
    // Check and run the empty checkpoint before blocking so the empty checkpoint will work in the
    // presence of threads blocking for weak ref access.
    self->CheckEmptyCheckpointFromWeakRefAccess(Locks::reference_processor_lock_);
    condition_.WaitHoldingLocks(self);
  }

  
  
  // std::ostringstream jweezy;
  // int max_region = 0;
  // int BYTES_TO_PRINT = 1000;
  // void* holder = (void*)reference->GetReferent();
  
  // max_region = memory_region_approximation6(holder,BYTES_TO_PRINT,BYTES_TO_PRINT/5);

  // BYTES_TO_PRINT = max_region;
  // if(BYTES_TO_PRINT > 0){
  //   jweezy << android::base::StringPrintf("JACK REFERENCE PROCESSOR LOG: GETTING REF AT %p: \t",holder);
    
  //   for(int j =0; j < BYTES_TO_PRINT; j++){
  //     jweezy << android::base::StringPrintf("%x ", ((char*)holder)[j] );//Log bytes at address
  //   }
  //   jweezy << "\t";
  // }

  // int length = jweezy.str().length();
  // std::ostringstream ss;
  // std::ostringstream header;
  // int spacer = (5120-header.str().length());
  // header << "JACK REFERENT PROCESSOR LOG: " << " CONT.\t";
  // if (length > 5120){
  //   for(int i = 0; (i)*spacer < length; i++){
  //     if (i > 0){
  //       ss << header.str();
  //     }
  //     ss << jweezy.str().substr(i* (spacer),(i+1)*spacer);
  //     LOG(INFO) << ss.str();
  //     ss.str("");
  //   }
  // }else{         
  //   LOG(INFO) << jweezy.str();
  // }

  return reference->GetReferent();
}

void ReferenceProcessor::StartPreservingReferences(Thread* self) {
  MutexLock mu(self, *Locks::reference_processor_lock_);
  preserving_references_ = true;
}

void ReferenceProcessor::StopPreservingReferences(Thread* self) {
  MutexLock mu(self, *Locks::reference_processor_lock_);
  preserving_references_ = false;
  // We are done preserving references, some people who are blocked may see a marked referent.
  condition_.Broadcast(self);
}

// Process reference class instances and schedule finalizations.
void ReferenceProcessor::ProcessReferences(bool concurrent,
                                           TimingLogger* timings,
                                           bool clear_soft_references,
                                           collector::GarbageCollector* collector) {
  TimingLogger::ScopedTiming t(concurrent ? __FUNCTION__ : "(Paused)ProcessReferences", timings);
  Thread* self = Thread::Current();
  {
    MutexLock mu(self, *Locks::reference_processor_lock_);
    collector_ = collector;
    if (!kUseReadBarrier) {
      CHECK_EQ(SlowPathEnabled(), concurrent) << "Slow path must be enabled iff concurrent";
    } else {
      // Weak ref access is enabled at Zygote compaction by SemiSpace (concurrent == false).
      CHECK_EQ(!self->GetWeakRefAccessEnabled(), concurrent);
    }
  }
  if (kIsDebugBuild && collector->IsTransactionActive()) {
    // In transaction mode, we shouldn't enqueue any Reference to the queues.
    // See DelayReferenceReferent().
    DCHECK(soft_reference_queue_.IsEmpty());
    DCHECK(weak_reference_queue_.IsEmpty());
    DCHECK(finalizer_reference_queue_.IsEmpty());
    DCHECK(phantom_reference_queue_.IsEmpty());
  }
  // Unless required to clear soft references with white references, preserve some white referents.
  if (!clear_soft_references) {
    TimingLogger::ScopedTiming split(concurrent ? "ForwardSoftReferences" :
        "(Paused)ForwardSoftReferences", timings);
    if (concurrent) {
      StartPreservingReferences(self);
    }
    // TODO: Add smarter logic for preserving soft references. The behavior should be a conditional
    // mark if the SoftReference is supposed to be preserved.
    soft_reference_queue_.ForwardSoftReferences(collector);
    collector->ProcessMarkStack();
    if (concurrent) {
      StopPreservingReferences(self);
    }
  }
  // Clear all remaining soft and weak references with white referents.
  soft_reference_queue_.ClearWhiteReferences(&cleared_references_, collector);
  weak_reference_queue_.ClearWhiteReferences(&cleared_references_, collector);
  {
    TimingLogger::ScopedTiming t2(concurrent ? "EnqueueFinalizerReferences" :
        "(Paused)EnqueueFinalizerReferences", timings);
    if (concurrent) {
      StartPreservingReferences(self);
    }
    // Preserve all white objects with finalize methods and schedule them for finalization.
    finalizer_reference_queue_.EnqueueFinalizerReferences(&cleared_references_, collector);
    collector->ProcessMarkStack();
    if (concurrent) {
      StopPreservingReferences(self);
    }
  }
  // Clear all finalizer referent reachable soft and weak references with white referents.
  soft_reference_queue_.ClearWhiteReferences(&cleared_references_, collector);
  weak_reference_queue_.ClearWhiteReferences(&cleared_references_, collector);
  // Clear all phantom references with white referents.
  phantom_reference_queue_.ClearWhiteReferences(&cleared_references_, collector);
  // At this point all reference queues other than the cleared references should be empty.
  DCHECK(soft_reference_queue_.IsEmpty());
  DCHECK(weak_reference_queue_.IsEmpty());
  DCHECK(finalizer_reference_queue_.IsEmpty());
  DCHECK(phantom_reference_queue_.IsEmpty());
  {
    MutexLock mu(self, *Locks::reference_processor_lock_);
    // Need to always do this since the next GC may be concurrent. Doing this for only concurrent
    // could result in a stale is_marked_callback_ being called before the reference processing
    // starts since there is a small window of time where slow_path_enabled_ is enabled but the
    // callback isn't yet set.
    collector_ = nullptr;
    if (!kUseReadBarrier && concurrent) {
      // Done processing, disable the slow path and broadcast to the waiters.
      DisableSlowPath(self);
    }
  }
}

// Process the "referent" field in a java.lang.ref.Reference.  If the referent has not yet been
// marked, put it on the appropriate list in the heap for later processing.
void ReferenceProcessor::DelayReferenceReferent(ObjPtr<mirror::Class> klass,
                                                ObjPtr<mirror::Reference> ref,
                                                collector::GarbageCollector* collector) {
  // klass can be the class of the old object if the visitor already updated the class of ref.
  DCHECK(klass != nullptr);
  DCHECK(klass->IsTypeOfReferenceClass());
  mirror::HeapReference<mirror::Object>* referent = ref->GetReferentReferenceAddr();
  // do_atomic_update needs to be true because this happens outside of the reference processing
  // phase.
  if (!collector->IsNullOrMarkedHeapReference(referent, /*do_atomic_update=*/true)) {
    if (UNLIKELY(collector->IsTransactionActive())) {
      // In transaction mode, keep the referent alive and avoid any reference processing to avoid the
      // issue of rolling back reference processing.  do_atomic_update needs to be true because this
      // happens outside of the reference processing phase.
      if (!referent->IsNull()) {
        collector->MarkHeapReference(referent, /*do_atomic_update=*/ true);
      }
      return;
    }
    Thread* self = Thread::Current();
    // TODO: Remove these locks, and use atomic stacks for storing references?
    // We need to check that the references haven't already been enqueued since we can end up
    // scanning the same reference multiple times due to dirty cards.
    if (klass->IsSoftReferenceClass()) {
      soft_reference_queue_.AtomicEnqueueIfNotEnqueued(self, ref);
    } else if (klass->IsWeakReferenceClass()) {
      weak_reference_queue_.AtomicEnqueueIfNotEnqueued(self, ref);
    } else if (klass->IsFinalizerReferenceClass()) {
      finalizer_reference_queue_.AtomicEnqueueIfNotEnqueued(self, ref);
    } else if (klass->IsPhantomReferenceClass()) {
      phantom_reference_queue_.AtomicEnqueueIfNotEnqueued(self, ref);
    } else {
      LOG(FATAL) << "Invalid reference type " << klass->PrettyClass() << " " << std::hex
                 << klass->GetAccessFlags();
    }
  }
}

void ReferenceProcessor::UpdateRoots(IsMarkedVisitor* visitor) {
  cleared_references_.UpdateRoots(visitor);
}

class ClearedReferenceTask : public HeapTask {
 public:
  explicit ClearedReferenceTask(jobject cleared_references)
      : HeapTask(NanoTime()), cleared_references_(cleared_references) {
  }
  void Run(Thread* thread) override {
    ScopedObjectAccess soa(thread);
    jvalue args[1];
    args[0].l = cleared_references_;
    InvokeWithJValues(soa, nullptr, WellKnownClasses::java_lang_ref_ReferenceQueue_add, args);
    soa.Env()->DeleteGlobalRef(cleared_references_);
  }

 private:
  const jobject cleared_references_;
};

SelfDeletingTask* ReferenceProcessor::CollectClearedReferences(Thread* self) {
  Locks::mutator_lock_->AssertNotHeld(self);
  // By default we don't actually need to do anything. Just return this no-op task to avoid having
  // to put in ifs.
  std::unique_ptr<SelfDeletingTask> result(new FunctionTask([](Thread*) {}));
  // When a runtime isn't started there are no reference queues to care about so ignore.
  if (!cleared_references_.IsEmpty()) {
    if (LIKELY(Runtime::Current()->IsStarted())) {
      jobject cleared_references;
      {
        ReaderMutexLock mu(self, *Locks::mutator_lock_);
        cleared_references = self->GetJniEnv()->GetVm()->AddGlobalRef(
            self, cleared_references_.GetList());
      }
      if (kAsyncReferenceQueueAdd) {
        // TODO: This can cause RunFinalization to terminate before newly freed objects are
        // finalized since they may not be enqueued by the time RunFinalization starts.
        Runtime::Current()->GetHeap()->GetTaskProcessor()->AddTask(
            self, new ClearedReferenceTask(cleared_references));
      } else {
        result.reset(new ClearedReferenceTask(cleared_references));
      }
    }
    cleared_references_.Clear();
  }
  return result.release();
}

void ReferenceProcessor::ClearReferent(ObjPtr<mirror::Reference> ref) {
  Thread* self = Thread::Current();
  MutexLock mu(self, *Locks::reference_processor_lock_);
  // Need to wait until reference processing is done since IsMarkedHeapReference does not have a
  // CAS. If we do not wait, it can result in the GC un-clearing references due to race conditions.
  // This also handles the race where the referent gets cleared after a null check but before
  // IsMarkedHeapReference is called.
  WaitUntilDoneProcessingReferences(self);
  if (Runtime::Current()->IsActiveTransaction()) {
    ref->ClearReferent<true>();
  } else {
    ref->ClearReferent<false>();
  }
}

void ReferenceProcessor::WaitUntilDoneProcessingReferences(Thread* self) {
  // Wait until we are done processing reference.
  while ((!kUseReadBarrier && SlowPathEnabled()) ||
         (kUseReadBarrier && !self->GetWeakRefAccessEnabled())) {
    // Check and run the empty checkpoint before blocking so the empty checkpoint will work in the
    // presence of threads blocking for weak ref access.
    self->CheckEmptyCheckpointFromWeakRefAccess(Locks::reference_processor_lock_);
    condition_.WaitHoldingLocks(self);
  }
}

bool ReferenceProcessor::MakeCircularListIfUnenqueued(
    ObjPtr<mirror::FinalizerReference> reference) {
  Thread* self = Thread::Current();
  MutexLock mu(self, *Locks::reference_processor_lock_);
  WaitUntilDoneProcessingReferences(self);
  // At this point, since the sentinel of the reference is live, it is guaranteed to not be
  // enqueued if we just finished processing references. Otherwise, we may be doing the main GC
  // phase. Since we are holding the reference processor lock, it guarantees that reference
  // processing can't begin. The GC could have just enqueued the reference one one of the internal
  // GC queues, but since we hold the lock finalizer_reference_queue_ lock it also prevents this
  // race.
  MutexLock mu2(self, *Locks::reference_queue_finalizer_references_lock_);
  if (reference->IsUnprocessed()) {
    CHECK(reference->IsFinalizerReferenceInstance());
    reference->SetPendingNext(reference);
    return true;
  }
  return false;
}

}  // namespace gc
}  // namespace art
