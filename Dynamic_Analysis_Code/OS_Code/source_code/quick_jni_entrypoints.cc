/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <android-base/logging.h>
#include <sys/utsname.h>
#include <fstream>

#include "art_method-inl.h"
#include "base/casts.h"
#include "entrypoints/entrypoint_utils-inl.h"
#include "indirect_reference_table.h"
#include "mirror/object-inl.h"
#include "palette/palette.h"
#include "thread-inl.h"
#include "verify_object.h"
#include "gc/verification.h" //Memory address validator

// #define LOG_NDEBUG 0

// For methods that monitor JNI invocations and report their begin/end to
// palette hooks.
#define MONITOR_JNI(kind)                                \
  {                                                      \
    bool should_report = false;                          \
    PaletteShouldReportJniInvocations(&should_report);   \
    if (should_report) {                                 \
      kind(self->GetJniEnv());                           \
    }                                                    \
  }

namespace art {

static_assert(sizeof(IRTSegmentState) == sizeof(uint32_t), "IRTSegmentState size unexpected");
static_assert(std::is_trivial<IRTSegmentState>::value, "IRTSegmentState not trivial");

static inline void GoToRunnableFast(Thread* self) REQUIRES_SHARED(Locks::mutator_lock_);

extern void ReadBarrierJni(mirror::CompressedReference<mirror::Class>* declaring_class,
                           Thread* self ATTRIBUTE_UNUSED) {
  DCHECK(kUseReadBarrier);
  if (kUseBakerReadBarrier) {
    DCHECK(declaring_class->AsMirrorPtr() != nullptr)
        << "The class of a static jni call must not be null";
    // Check the mark bit and return early if it's already marked.
    if (LIKELY(declaring_class->AsMirrorPtr()->GetMarkBit() != 0)) {
      return;
    }
  }
  // Call the read barrier and update the handle.
  mirror::Class* to_ref = ReadBarrier::BarrierForRoot(declaring_class);
  declaring_class->Assign(to_ref);
}

// Called on entry to fast JNI, push a new local reference table only.
extern uint32_t JniMethodFastStart(Thread* self) {
  JNIEnvExt* env = self->GetJniEnv();
  DCHECK(env != nullptr);
  uint32_t saved_local_ref_cookie = bit_cast<uint32_t>(env->GetLocalRefCookie());
  env->SetLocalRefCookie(env->GetLocalsSegmentState());

  if (kIsDebugBuild) {
    ArtMethod* native_method = *self->GetManagedStack()->GetTopQuickFrame();
    CHECK(native_method->IsFastNative()) << native_method->PrettyMethod();
  }

  return saved_local_ref_cookie;
}

// Called on entry to JNI, transition out of Runnable and release share of mutator_lock_.
extern uint32_t JniMethodStart(Thread* self) {
  JNIEnvExt* env = self->GetJniEnv();
  // JavaVMExt* vm = env->GetVm();
  // ScopedObjectAccess soa(env);
  
  DCHECK(env != nullptr);
  uint32_t saved_local_ref_cookie = bit_cast<uint32_t>(env->GetLocalRefCookie());
  env->SetLocalRefCookie(env->GetLocalsSegmentState());

  if (kIsDebugBuild) {
    ArtMethod* native_method = *self->GetManagedStack()->GetTopQuickFrame();
    CHECK(!native_method->IsFastNative()) << native_method->PrettyMethod();
  }

  //Dumping the local Reference tables to info stream
  // env->DumpReferenceTables(LOG_STREAM(INFO));
  
  // soa.Vm()->DumpReferenceTables(LOG_STREAM(INFO));

  // Transition out of runnable.
  self->TransitionFromRunnableToSuspended(kNative);
  return saved_local_ref_cookie;
}

extern uint32_t JniMethodStartSynchronized(jobject to_lock, Thread* self) {
  self->DecodeJObject(to_lock)->MonitorEnter(self);
  return JniMethodStart(self);
}

// TODO: NO_THREAD_SAFETY_ANALYSIS due to different control paths depending on fast JNI.
static void GoToRunnable(Thread* self) NO_THREAD_SAFETY_ANALYSIS {
  if (kIsDebugBuild) {
    ArtMethod* native_method = *self->GetManagedStack()->GetTopQuickFrame();
    CHECK(!native_method->IsFastNative()) << native_method->PrettyMethod();
  }


  self->TransitionFromSuspendedToRunnable();
}

ALWAYS_INLINE static inline void GoToRunnableFast(Thread* self) {
  if (kIsDebugBuild) {
    // Should only enter here if the method is @FastNative.
    ArtMethod* native_method = *self->GetManagedStack()->GetTopQuickFrame();
    CHECK(native_method->IsFastNative()) << native_method->PrettyMethod();
  }

  // When we are in @FastNative, we are already Runnable.
  // Only do a suspend check on the way out of JNI.
  if (UNLIKELY(self->TestAllFlags())) {
    // In fast JNI mode we never transitioned out of runnable. Perform a suspend check if there
    // is a flag raised.
    DCHECK(Locks::mutator_lock_->IsSharedHeld(self));
    self->CheckSuspend();
  }
}

static void PopLocalReferences(uint32_t saved_local_ref_cookie, Thread* self)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  JNIEnvExt* env = self->GetJniEnv();
  if (UNLIKELY(env->IsCheckJniEnabled())) {
    env->CheckNoHeldMonitors();
  }

  // Adding code for thread dump(Does not work currently)
  // self->Dump(LOG_STREAM(INFO),true,NULL,true);

  env->SetLocalSegmentState(env->GetLocalRefCookie());
  env->SetLocalRefCookie(bit_cast<IRTSegmentState>(saved_local_ref_cookie));
}

// TODO: annotalysis disabled as monitor semantics are maintained in Java code.
static inline void UnlockJniSynchronizedMethod(jobject locked, Thread* self)
    NO_THREAD_SAFETY_ANALYSIS REQUIRES(!Roles::uninterruptible_) {
  // Save any pending exception over monitor exit call.
  ObjPtr<mirror::Throwable> saved_exception = nullptr;
  if (UNLIKELY(self->IsExceptionPending())) {
    saved_exception = self->GetException();
    self->ClearException();
  }
  // Decode locked object and unlock, before popping local references.
  self->DecodeJObject(locked)->MonitorExit(self);
  if (UNLIKELY(self->IsExceptionPending())) {
    LOG(FATAL) << "Synchronized JNI code returning with an exception:\n"
        << saved_exception->Dump()
        << "\nEncountered second exception during implicit MonitorExit:\n"
        << self->GetException()->Dump();
  }
  // Restore pending exception.
  if (saved_exception != nullptr) {
    self->SetException(saved_exception);
  }
}

// TODO: These should probably be templatized or macro-ized.
// Otherwise there's just too much repetitive boilerplate.

extern void JniMethodEnd(uint32_t saved_local_ref_cookie, Thread* self) {
  
  // JNIEnvExt* env = self->GetJniEnv();

    

  //Dumping the local Reference tables to info stream
  // env->DumpReferenceTables(LOG_STREAM(INFO));
  // self->Dump(LOG_STREAM(INFO),true);
  // self->DumpJavaStack(LOG_STREAM(INFO),true);


  GoToRunnable(self);
  PopLocalReferences(saved_local_ref_cookie, self);
}

extern void JniMethodFastEnd(uint32_t saved_local_ref_cookie, Thread* self) {
  GoToRunnableFast(self);
  PopLocalReferences(saved_local_ref_cookie, self);
}

extern void JniMethodEndSynchronized(uint32_t saved_local_ref_cookie,
                                     jobject locked,
                                     Thread* self) {
  GoToRunnable(self);
  UnlockJniSynchronizedMethod(locked, self);  // Must decode before pop.
  PopLocalReferences(saved_local_ref_cookie, self);
}

// Common result handling for EndWithReference.
static mirror::Object* JniMethodEndWithReferenceHandleResult(jobject result,
                                                             uint32_t saved_local_ref_cookie,
                                                             Thread* self)
    NO_THREAD_SAFETY_ANALYSIS {
  // Must decode before pop. The 'result' may not be valid in case of an exception, though.
  ObjPtr<mirror::Object> o;
  if (!self->IsExceptionPending()) {
    o = self->DecodeJObject(result);
  }
  PopLocalReferences(saved_local_ref_cookie, self);
  // Process result.
  if (UNLIKELY(self->GetJniEnv()->IsCheckJniEnabled())) {
    // CheckReferenceResult can resolve types.
    StackHandleScope<1> hs(self);
    HandleWrapperObjPtr<mirror::Object> h_obj(hs.NewHandleWrapper(&o));
    CheckReferenceResult(h_obj, self);
  }
  VerifyObject(o);
  return o.Ptr();
}

extern mirror::Object* JniMethodFastEndWithReference(jobject result,
                                                     uint32_t saved_local_ref_cookie,
                                                     Thread* self) {
  GoToRunnableFast(self);
  return JniMethodEndWithReferenceHandleResult(result, saved_local_ref_cookie, self);
}

extern mirror::Object* JniMethodEndWithReference(jobject result,
                                                 uint32_t saved_local_ref_cookie,
                                                 Thread* self) {
  GoToRunnable(self);
  return JniMethodEndWithReferenceHandleResult(result, saved_local_ref_cookie, self);
}

extern mirror::Object* JniMethodEndWithReferenceSynchronized(jobject result,
                                                             uint32_t saved_local_ref_cookie,
                                                             jobject locked,
                                                             Thread* self) {
  GoToRunnable(self);
  UnlockJniSynchronizedMethod(locked, self);
  return JniMethodEndWithReferenceHandleResult(result, saved_local_ref_cookie, self);
}


int max_readable_bytes3(void *ptr,int max) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    std::ifstream maps_file("/proc/self/maps");
    if (!maps_file) {
        perror("Failed to open /proc/self/maps");
        return -1;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        uintptr_t start, end;
        char perms[5];
        std::istringstream iss(line);
        iss >> std::hex >> start;
        iss.ignore(1); // Ignore the '-' character
        iss >> std::hex >> end;
        iss >> perms;
        if (!iss.fail() && addr >= start && addr < end && perms[0] == 'r') {
            int distance_to_page =  end - addr;
            if(distance_to_page < max){
              return distance_to_page;
            }else{
              return max;
            }
        }
    }

    return -1;
}

extern uint64_t GenericJniMethodEnd(Thread* self,
                                    uint32_t saved_local_ref_cookie,
                                    jvalue result,
                                    uint64_t result_f,
                                    ArtMethod* called)
    // TODO: NO_THREAD_SAFETY_ANALYSIS as GoToRunnable() is NO_THREAD_SAFETY_ANALYSIS
    NO_THREAD_SAFETY_ANALYSIS {
  bool critical_native = called->IsCriticalNative();
  bool fast_native = called->IsFastNative();
  bool normal_native = !critical_native && !fast_native;

  // @CriticalNative does not do a state transition. @FastNative usually does not do a state
  // transition either but it performs a suspend check that may do state transitions.
  if (LIKELY(normal_native)) {
    MONITOR_JNI(PaletteNotifyEndJniInvocation);
    GoToRunnable(self);
  } else if (fast_native) {
    GoToRunnableFast(self);
  }
  // We need the mutator lock (i.e., calling GoToRunnable()) before accessing the shorty or the
  // locked object.
  if (called->IsSynchronized()) {
    DCHECK(normal_native) << "@FastNative/@CriticalNative and synchronize is not supported";
    jobject lock = GetGenericJniSynchronizationObject(self, called);
    DCHECK(lock != nullptr);
    UnlockJniSynchronizedMethod(lock, self);
  }
  char return_shorty_char = called->GetShorty()[0];
  
  
  
  // const art::gc::Verification* v = Runtime::Current()->GetHeap()->GetVerification();
  
  std::ostringstream jweezy;
  char ret_typing = return_shorty_char;
  int BYTES_TO_PRINT = 500;
  bool can_log = true;
  uint8_t z_ret;
  int8_t b_ret;
  uint16_t c_ret;
  int16_t s_ret;
  int32_t i_ret;
  int64_t j_ret;
  float f_ret;
  double d_ret;
  uint64_t l_ret;
  void* v_cast;
  void* holder = 0;
  // int max_region = 0;
  // unsigned long vt;


  jweezy << android::base::StringPrintf("JACK LOG: JNIGENERIC END\t") << called->PrettyMethod() <<"\t";
  switch(ret_typing){
    case 'B':{
      b_ret = result.b;
      jweezy << android::base::StringPrintf("\tRet: %d\t",b_ret);
      break;
    }
    case 'C':{
      c_ret = result.c;
      jweezy << android::base::StringPrintf("\tRet: %d\t",c_ret);
      break;
    }
    case 'D':{
      d_ret = result.d;
      jweezy << android::base::StringPrintf("\tRet: %lf\t",d_ret);
      break;
    }
    case 'F':{
      f_ret = result.f;
      jweezy << android::base::StringPrintf("\tRet: %f\t",f_ret);
      break;
    }
    case 'I':{
      i_ret = result.i;
      jweezy << android::base::StringPrintf("\tRet: %d\t",i_ret);
      break;
    }
    case 'J':{
      j_ret = result.j;
      
    

      BYTES_TO_PRINT = max_readable_bytes3((void*)j_ret,BYTES_TO_PRINT);
        
      if(BYTES_TO_PRINT > 0){
        jweezy << android::base::StringPrintf("\t LONG ADDRESS ");
        holder = (void*)j_ret;
        jweezy << android::base::StringPrintf("\tBytes at %p: ", holder);
        for(int j =0; j < BYTES_TO_PRINT; j++){
            jweezy << android::base::StringPrintf(" %x", ((char*)holder)[j] );//Log bytes at address
            continue;      

        }
         
        jweezy << "\t";
        

      }else{
        jweezy << android::base::StringPrintf("\tRet: %lx\t",(unsigned long)j_ret);
      }
    
    break;
    }
    case 'L':{
      l_ret = reinterpret_cast<uint64_t>(JniMethodEndWithReferenceHandleResult(result.l, saved_local_ref_cookie, self));
      v_cast = (void*)l_ret;
      jweezy << android::base::StringPrintf("\tRet: %p\t",v_cast);
      if(v_cast != nullptr && v_cast != 0){
        BYTES_TO_PRINT = max_readable_bytes3((void*)v_cast,BYTES_TO_PRINT);

        if(BYTES_TO_PRINT > 0){
          jweezy << android::base::StringPrintf("\tBytes at %p: ", (void*)v_cast);
          
          for(int j =0; j < BYTES_TO_PRINT; j++){
            jweezy << android::base::StringPrintf("%x ", ((char*)v_cast)[j] );//Log bytes at address
          }
          jweezy << "\t";    
                
        }else{
          jweezy << "\tAddress NULL\t";
        }
      break;
      }
      break;
    }
    case 'S':{
      s_ret = result.s;
      jweezy << android::base::StringPrintf("\tRet: %d\t",s_ret);
      break;
    }
    case 'Z':{
      z_ret = result.z;
      jweezy << android::base::StringPrintf("\tRet: %d\t",z_ret);
      break;
    }
    default:{
      can_log= false;
      break;
    }

  }

  if (can_log){
    int length = jweezy.str().length();
    std::ostringstream ss;
    std::ostringstream header;
    int spacer = (5120-header.str().length());
    header << "JACK LOG: " << called->PrettyMethod() << " CONT.\t";
    if (length > 5120){
      for(int i = 0; (i)*spacer < length; i++){
        if (i > 0){
          ss << header.str();
        }
        ss << jweezy.str().substr(i* (spacer),(i+1)*spacer);
        LOG(INFO) << ss.str();
        ss.str("");
      }
    }else{         
      LOG(INFO) << jweezy.str();
    }

  }
  


  if (return_shorty_char == 'L') {
    // l_ret = reinterpret_cast<uint64_t>(JniMethodEndWithReferenceHandleResult(result.l, saved_local_ref_cookie, self));
    return l_ret;
  } else {
    if (LIKELY(!critical_native)) {
      PopLocalReferences(saved_local_ref_cookie, self);
    }
    switch (return_shorty_char) {
      case 'F': {
        if (kRuntimeISA == InstructionSet::kX86) {
          // Convert back the result to float.
          double d = bit_cast<double, uint64_t>(result_f);
          return bit_cast<uint32_t, float>(static_cast<float>(d));
        } else {
          return result_f;
        }
      }
      case 'D':
        return result_f;
      case 'Z':
        return result.z;
      case 'B':
        return result.b;
      case 'C':
        return result.c;
      case 'S':
        return result.s;
      case 'I':
        return result.i;
      case 'J':
        return result.j;
      case 'V':
        return 0;
      default:
        LOG(FATAL) << "Unexpected return shorty character " << return_shorty_char;
        UNREACHABLE();
    }
  }
}

extern uint32_t JniMonitoredMethodStart(Thread* self) {
  uint32_t result = JniMethodStart(self);
  MONITOR_JNI(PaletteNotifyBeginJniInvocation);
  return result;
}

extern uint32_t JniMonitoredMethodStartSynchronized(jobject to_lock, Thread* self) {
  uint32_t result = JniMethodStartSynchronized(to_lock, self);
  MONITOR_JNI(PaletteNotifyBeginJniInvocation);
  return result;
}

extern void JniMonitoredMethodEnd(uint32_t saved_local_ref_cookie, Thread* self) {
  MONITOR_JNI(PaletteNotifyEndJniInvocation);
  return JniMethodEnd(saved_local_ref_cookie, self);
}

extern void JniMonitoredMethodEndSynchronized(uint32_t saved_local_ref_cookie,
                                             jobject locked,
                                             Thread* self) {
  MONITOR_JNI(PaletteNotifyEndJniInvocation);
  return JniMethodEndSynchronized(saved_local_ref_cookie, locked, self);
}

extern mirror::Object* JniMonitoredMethodEndWithReference(jobject result,
                                                          uint32_t saved_local_ref_cookie,
                                                          Thread* self) {
  MONITOR_JNI(PaletteNotifyEndJniInvocation);
  return JniMethodEndWithReference(result, saved_local_ref_cookie, self);
}

extern mirror::Object* JniMonitoredMethodEndWithReferenceSynchronized(
    jobject result,
    uint32_t saved_local_ref_cookie,
    jobject locked,
    Thread* self) {
  MONITOR_JNI(PaletteNotifyEndJniInvocation);
  return JniMethodEndWithReferenceSynchronized(result, saved_local_ref_cookie, locked, self);
}

}  // namespace art
