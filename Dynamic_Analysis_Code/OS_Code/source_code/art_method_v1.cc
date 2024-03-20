/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include "art_method.h"

#include <algorithm>
#include <cstddef>
#include <sys/mman.h> //ADDED
#include <fstream>


#include "android-base/stringprintf.h"

#include "arch/context.h"
#include "art_method-inl.h"
#include "base/enums.h"
#include "base/stl_util.h"
#include "class_linker-inl.h"
#include "class_root-inl.h"
#include "debugger.h"
#include "dex/class_accessor-inl.h"
#include "dex/descriptors_names.h"
#include "dex/dex_file-inl.h"
#include "dex/dex_file_exception_helpers.h"
#include "dex/dex_instruction.h"
#include "dex/dex_instruction-inl.h"// ADDED
#include "dex/code_item_accessors-inl.h" //ADDED
#include "dex/signature-inl.h"
#include "entrypoints/runtime_asm_entrypoints.h"
#include "gc/accounting/card_table-inl.h"
#include "gc/verification.h" //ADDED
#include "hidden_api.h"
#include "interpreter/interpreter.h"
#include "jit/jit.h"
#include "jit/jit_code_cache.h"
#include "jit/profiling_info.h"
#include "jni/jni_internal.h"
#include "mirror/class-inl.h"
#include "mirror/class_ext-inl.h"
#include "mirror/executable.h"
#include "mirror/object-inl.h"
#include "mirror/object_array-inl.h"
#include "mirror/string.h"
#include "oat_file-inl.h"
#include "quicken_info.h"
#include "runtime_callbacks.h"
#include "scoped_thread_state_change-inl.h"
#include "vdex_file.h"

namespace art {

using android::base::StringPrintf;

extern "C" void art_quick_invoke_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
                                      const char*);
extern "C" void art_quick_invoke_static_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
                                             const char*);

// Enforce that we have the right index for runtime methods.
static_assert(ArtMethod::kRuntimeMethodDexMethodIndex == dex::kDexNoIndex,
              "Wrong runtime-method dex method index");

ArtMethod* ArtMethod::GetCanonicalMethod(PointerSize pointer_size) {
  if (LIKELY(!IsCopied())) {
    return this;
  } else {
    ObjPtr<mirror::Class> declaring_class = GetDeclaringClass();
    DCHECK(declaring_class->IsInterface());
    ArtMethod* ret = declaring_class->FindInterfaceMethod(GetDexCache(),
                                                          GetDexMethodIndex(),
                                                          pointer_size);
    DCHECK(ret != nullptr);
    return ret;
  }
}

ArtMethod* ArtMethod::GetNonObsoleteMethod() {
  if (LIKELY(!IsObsolete())) {
    return this;
  }
  DCHECK_EQ(kRuntimePointerSize, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  if (IsDirect()) {
    return &GetDeclaringClass()->GetDirectMethodsSlice(kRuntimePointerSize)[GetMethodIndex()];
  } else {
    return GetDeclaringClass()->GetVTableEntry(GetMethodIndex(), kRuntimePointerSize);
  }
}

ArtMethod* ArtMethod::GetSingleImplementation(PointerSize pointer_size) {
  if (IsInvokable()) {
    // An invokable method single implementation is itself.
    return this;
  }
  DCHECK(!IsDefaultConflicting());
  ArtMethod* m = reinterpret_cast<ArtMethod*>(GetDataPtrSize(pointer_size));
  CHECK(m == nullptr || !m->IsDefaultConflicting());
  return m;
}

ArtMethod* ArtMethod::FromReflectedMethod(const ScopedObjectAccessAlreadyRunnable& soa,
                                          jobject jlr_method) {
  ObjPtr<mirror::Executable> executable = soa.Decode<mirror::Executable>(jlr_method);
  DCHECK(executable != nullptr);
  return executable->GetArtMethod();
}

ObjPtr<mirror::DexCache> ArtMethod::GetObsoleteDexCache() {
  PointerSize pointer_size = kRuntimePointerSize;
  DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
  DCHECK(IsObsolete());
  ObjPtr<mirror::ClassExt> ext(GetDeclaringClass()->GetExtData());
  ObjPtr<mirror::PointerArray> obsolete_methods(ext.IsNull() ? nullptr : ext->GetObsoleteMethods());
  int32_t len = (obsolete_methods.IsNull() ? 0 : obsolete_methods->GetLength());
  DCHECK(len == 0 || len == ext->GetObsoleteDexCaches()->GetLength())
      << "len=" << len << " ext->GetObsoleteDexCaches()=" << ext->GetObsoleteDexCaches();
  // Using kRuntimePointerSize (instead of using the image's pointer size) is fine since images
  // should never have obsolete methods in them so they should always be the same.
  DCHECK_EQ(pointer_size, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  for (int32_t i = 0; i < len; i++) {
    if (this == obsolete_methods->GetElementPtrSize<ArtMethod*>(i, pointer_size)) {
      return ext->GetObsoleteDexCaches()->Get(i);
    }
  }
  CHECK(GetDeclaringClass()->IsObsoleteObject())
      << "This non-structurally obsolete method does not appear in the obsolete map of its class: "
      << GetDeclaringClass()->PrettyClass() << " Searched " << len << " caches.";
  CHECK_EQ(this,
           std::clamp(this,
                      &(*GetDeclaringClass()->GetMethods(pointer_size).begin()),
                      &(*GetDeclaringClass()->GetMethods(pointer_size).end())))
      << "class is marked as structurally obsolete method but not found in normal obsolete-map "
      << "despite not being the original method pointer for " << GetDeclaringClass()->PrettyClass();
  return GetDeclaringClass()->GetDexCache();
}

uint16_t ArtMethod::FindObsoleteDexClassDefIndex() {
  DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
  DCHECK(IsObsolete());
  const DexFile* dex_file = GetDexFile();
  const dex::TypeIndex declaring_class_type = dex_file->GetMethodId(GetDexMethodIndex()).class_idx_;
  const dex::ClassDef* class_def = dex_file->FindClassDef(declaring_class_type);
  CHECK(class_def != nullptr);
  return dex_file->GetIndexForClassDef(*class_def);
}

void ArtMethod::ThrowInvocationTimeError() {
  DCHECK(!IsInvokable());
  if (IsDefaultConflicting()) {
    ThrowIncompatibleClassChangeErrorForMethodConflict(this);
  } else {
    DCHECK(IsAbstract());
    ThrowAbstractMethodError(this);
  }
}

InvokeType ArtMethod::GetInvokeType() {
  // TODO: kSuper?
  if (IsStatic()) {
    return kStatic;
  } else if (GetDeclaringClass()->IsInterface()) {
    return kInterface;
  } else if (IsDirect()) {
    return kDirect;
  } else if (IsSignaturePolymorphic()) {
    return kPolymorphic;
  } else {
    return kVirtual;
  }
}

size_t ArtMethod::NumArgRegisters(const char* shorty) {
  CHECK_NE(shorty[0], '\0');
  uint32_t num_registers = 0;
  for (const char* s = shorty + 1; *s != '\0'; ++s) {
    if (*s == 'D' || *s == 'J') {
      num_registers += 2;
    } else {
      num_registers += 1;
    }
  }
  return num_registers;
}

bool ArtMethod::HasSameNameAndSignature(ArtMethod* other) {
  ScopedAssertNoThreadSuspension ants("HasSameNameAndSignature");
  const DexFile* dex_file = GetDexFile();
  const dex::MethodId& mid = dex_file->GetMethodId(GetDexMethodIndex());
  if (GetDexCache() == other->GetDexCache()) {
    const dex::MethodId& mid2 = dex_file->GetMethodId(other->GetDexMethodIndex());
    return mid.name_idx_ == mid2.name_idx_ && mid.proto_idx_ == mid2.proto_idx_;
  }
  const DexFile* dex_file2 = other->GetDexFile();
  const dex::MethodId& mid2 = dex_file2->GetMethodId(other->GetDexMethodIndex());
  if (!DexFile::StringEquals(dex_file, mid.name_idx_, dex_file2, mid2.name_idx_)) {
    return false;  // Name mismatch.
  }
  return dex_file->GetMethodSignature(mid) == dex_file2->GetMethodSignature(mid2);
}

ArtMethod* ArtMethod::FindOverriddenMethod(PointerSize pointer_size) {
  if (IsStatic()) {
    return nullptr;
  }
  ObjPtr<mirror::Class> declaring_class = GetDeclaringClass();
  ObjPtr<mirror::Class> super_class = declaring_class->GetSuperClass();
  uint16_t method_index = GetMethodIndex();
  ArtMethod* result = nullptr;
  // Did this method override a super class method? If so load the result from the super class'
  // vtable
  if (super_class->HasVTable() && method_index < super_class->GetVTableLength()) {
    result = super_class->GetVTableEntry(method_index, pointer_size);
  } else {
    // Method didn't override superclass method so search interfaces
    if (IsProxyMethod()) {
      result = GetInterfaceMethodIfProxy(pointer_size);
      DCHECK(result != nullptr);
    } else {
      ObjPtr<mirror::IfTable> iftable = GetDeclaringClass()->GetIfTable();
      for (size_t i = 0; i < iftable->Count() && result == nullptr; i++) {
        ObjPtr<mirror::Class> interface = iftable->GetInterface(i);
        for (ArtMethod& interface_method : interface->GetVirtualMethods(pointer_size)) {
          if (HasSameNameAndSignature(interface_method.GetInterfaceMethodIfProxy(pointer_size))) {
            result = &interface_method;
            break;
          }
        }
      }
    }
  }
  DCHECK(result == nullptr ||
         GetInterfaceMethodIfProxy(pointer_size)->HasSameNameAndSignature(
             result->GetInterfaceMethodIfProxy(pointer_size)));
  return result;
}

uint32_t ArtMethod::FindDexMethodIndexInOtherDexFile(const DexFile& other_dexfile,
                                                     uint32_t name_and_signature_idx) {
  const DexFile* dexfile = GetDexFile();
  const uint32_t dex_method_idx = GetDexMethodIndex();
  const dex::MethodId& mid = dexfile->GetMethodId(dex_method_idx);
  const dex::MethodId& name_and_sig_mid = other_dexfile.GetMethodId(name_and_signature_idx);
  DCHECK_STREQ(dexfile->GetMethodName(mid), other_dexfile.GetMethodName(name_and_sig_mid));
  DCHECK_EQ(dexfile->GetMethodSignature(mid), other_dexfile.GetMethodSignature(name_and_sig_mid));
  if (dexfile == &other_dexfile) {
    return dex_method_idx;
  }
  const char* mid_declaring_class_descriptor = dexfile->StringByTypeIdx(mid.class_idx_);
  const dex::TypeId* other_type_id = other_dexfile.FindTypeId(mid_declaring_class_descriptor);
  if (other_type_id != nullptr) {
    const dex::MethodId* other_mid = other_dexfile.FindMethodId(
        *other_type_id, other_dexfile.GetStringId(name_and_sig_mid.name_idx_),
        other_dexfile.GetProtoId(name_and_sig_mid.proto_idx_));
    if (other_mid != nullptr) {
      return other_dexfile.GetIndexForMethodId(*other_mid);
    }
  }
  return dex::kDexNoIndex;
}

uint32_t ArtMethod::FindCatchBlock(Handle<mirror::Class> exception_type,
                                   uint32_t dex_pc, bool* has_no_move_exception) {
  // Set aside the exception while we resolve its type.
  Thread* self = Thread::Current();
  StackHandleScope<1> hs(self);
  Handle<mirror::Throwable> exception(hs.NewHandle(self->GetException()));
  self->ClearException();
  // Default to handler not found.
  uint32_t found_dex_pc = dex::kDexNoIndex;
  // Iterate over the catch handlers associated with dex_pc.
  CodeItemDataAccessor accessor(DexInstructionData());
  for (CatchHandlerIterator it(accessor, dex_pc); it.HasNext(); it.Next()) {
    dex::TypeIndex iter_type_idx = it.GetHandlerTypeIndex();
    // Catch all case
    if (!iter_type_idx.IsValid()) {
      found_dex_pc = it.GetHandlerAddress();
      break;
    }
    // Does this catch exception type apply?
    ObjPtr<mirror::Class> iter_exception_type = ResolveClassFromTypeIndex(iter_type_idx);
    if (UNLIKELY(iter_exception_type == nullptr)) {
      // Now have a NoClassDefFoundError as exception. Ignore in case the exception class was
      // removed by a pro-guard like tool.
      // Note: this is not RI behavior. RI would have failed when loading the class.
      self->ClearException();
      // Delete any long jump context as this routine is called during a stack walk which will
      // release its in use context at the end.
      delete self->GetLongJumpContext();
      LOG(WARNING) << "Unresolved exception class when finding catch block: "
        << DescriptorToDot(GetTypeDescriptorFromTypeIdx(iter_type_idx));
    } else if (iter_exception_type->IsAssignableFrom(exception_type.Get())) {
      found_dex_pc = it.GetHandlerAddress();
      break;
    }
  }
  if (found_dex_pc != dex::kDexNoIndex) {
    const Instruction& first_catch_instr = accessor.InstructionAt(found_dex_pc);
    *has_no_move_exception = (first_catch_instr.Opcode() != Instruction::MOVE_EXCEPTION);
  }
  // Put the exception back.
  if (exception != nullptr) {
    self->SetException(exception.Get());
  }
  return found_dex_pc;
}


bool function_filter(std::string weezy){

  std::ifstream cmdline("/proc/self/cmdline");
  std::string processName;
  std::getline(cmdline, processName, '\0');

  const char* funcs[12] ={"tensor","tflite","pytorch","learning","audio","camera","video","image","stats","native","jni","Parcel"};

  for (int i=0; i< 12; i++){
    if(weezy.find(funcs[i]) != std::string::npos){
      return true;
    }
  }

  return false;
}

int max_readable_bytes(void *ptr,int max) {
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

void capture_arguments( uint32_t* args, size_t args_size, const char* shorty, std::ostringstream& jweezy, bool is_not_static){
  unsigned long l;
  float fl;
  double dl;
  uint32_t vt;
  int tmp;
  int BYTES_TO_PRINT = 500;

  char* tmp_args2 = (char*)args;
  // int max_region = 0;
  int arg_size_tmp = (int) args_size;
  uintptr_t holder;
  int c = 0;
  bool log_longs = false;

  if(is_not_static){
    tmp_args2+=4;
  }

  c=1;
  //For loop that increments over the args.
  for(int i =0; i < (int)(arg_size_tmp); ){
      BYTES_TO_PRINT = 500;
      if( shorty[c] != '\0'){
        switch(shorty[c]) {
        case 'J':{
            l = ( ((unsigned long*)tmp_args2)[0]);
            if(l != 0 && l >= 0x10000000 && log_longs){
              BYTES_TO_PRINT = max_readable_bytes((void*)l,BYTES_TO_PRINT);

              jweezy << StringPrintf("\tBytes at %lu: ", l);
              if(BYTES_TO_PRINT > 0){
                for(int j =0; j < BYTES_TO_PRINT; j++){
                  jweezy << StringPrintf("%x ", ((char*)l)[j] );//Log bytes at address
                }
                jweezy << "\t";
              }else{
                jweezy << StringPrintf("\tARG %d: %lx\t", i, l);//Log each address
              }
            }else{
              jweezy << StringPrintf("\tARG %d: %lx\t", i, l);//Log each address
            }
            i+=8;
            tmp_args2+=8;
            break;
        }
        case 'F':{
            fl = ( ((float*)tmp_args2)[0]);
            jweezy << StringPrintf("\tARG %d: %f\t", i, fl);//Log each address
            i+=4;
            tmp_args2+=4;
            break;
        }
        case 'D':{
            dl = ( ((double*)tmp_args2)[0]);
            jweezy << StringPrintf("\tARG %d: %lf\t", i, dl);//Log each address
            i+=8;
            tmp_args2+=8;
            break;
        }
        case 'L':{
            vt = (((uint32_t*)tmp_args2)[0]);
            jweezy << StringPrintf("\tARG %d: %x\t", i, vt);
            
            StackReference<mirror::Object>* o;

            if(vt != 0){
              o = reinterpret_cast<StackReference<mirror::Object>*>(vt);
            }else{
              o = nullptr;
            }
            
            if(o != nullptr){
              if (!o->IsNull()){
                holder = reinterpret_cast<uintptr_t>(o);

                BYTES_TO_PRINT = max_readable_bytes((void*)holder,BYTES_TO_PRINT);

                if(BYTES_TO_PRINT > 0){
                  jweezy << StringPrintf("\tBytes at %u: ", (uint32_t)holder);
                  
                  for(int j =0; j < BYTES_TO_PRINT; j++){
                    jweezy << StringPrintf("%x ", ((char*)holder)[j] );//Log bytes at address
                  }
                  jweezy << "\t";
                
                }else{
                  jweezy << "\tEXECUTABLE ONLY(THIS IS WEIRD)\t";
                }
                }else{
                  jweezy << "\tAddress NULL\t";
                }
                      
                  }else{
                    jweezy << "NULL\t";
                  }

                i+=4;
                tmp_args2+=4;
                break;
            }
            default:{
                tmp = ( ((int*)tmp_args2)[0]);
                jweezy << StringPrintf("\tARG %d: %x\t", i, tmp);//Log each address
                i+=4;
                tmp_args2+=4;
                break;
            }
            }
            c+=1;
            
          }else{
            i = arg_size_tmp;
          }


      }
}


std::unique_ptr<char[]> indexString(const DexFile* pDexFile,
                                           const Instruction* pDecInsn,
                                           size_t bufSize) {


  using u2 = uint16_t;
  using u4 = uint32_t;

  std::unique_ptr<char[]> buf(new char[bufSize]);
  // Determine index and width of the string.
  u4 index = 0;
  u2 secondary_index = 0;
  u4 width = 4;
  switch (Instruction::FormatOf(pDecInsn->Opcode())) {
    // SOME NOT SUPPORTED:
    // case Instruction::k20bc:
    case Instruction::k21c:
    case Instruction::k35c:
    // case Instruction::k35ms:
    case Instruction::k3rc:
    // case Instruction::k3rms:
    // case Instruction::k35mi:
    // case Instruction::k3rmi:
      index = pDecInsn->VRegB();
      width = 4;
      break;
    case Instruction::k31c:
      index = pDecInsn->VRegB();
      width = 8;
      break;
    case Instruction::k22c:
    // case Instruction::k22cs:
      index = pDecInsn->VRegC();
      width = 4;
      break;
    case Instruction::k45cc:
    case Instruction::k4rcc:
      index = pDecInsn->VRegB();
      secondary_index = pDecInsn->VRegH();
      width = 4;
      break;
    default:
      break;
  }  // switch

  // Determine index type.
  size_t outSize = 0;
  switch (Instruction::IndexTypeOf(pDecInsn->Opcode())) {
    case Instruction::kIndexUnknown:
      // This function should never get called for this type, but do
      // something sensible here, just to help with debugging.
      outSize = snprintf(buf.get(), bufSize, "<unknown-index>");
      break;
    case Instruction::kIndexNone:
      // This function should never get called for this type, but do
      // something sensible here, just to help with debugging.
      outSize = snprintf(buf.get(), bufSize, "<no-index>");
      break;
    case Instruction::kIndexTypeRef:
      if (index < pDexFile->GetHeader().type_ids_size_) {
        const char* tp = pDexFile->StringByTypeIdx(dex::TypeIndex(index));
        outSize = snprintf(buf.get(), bufSize, "%s // type@%0*x", tp, width, index);
      } else {
        outSize = snprintf(buf.get(), bufSize, "<type?> // type@%0*x", width, index);
      }
      break;
    case Instruction::kIndexStringRef:
      if (index < pDexFile->GetHeader().string_ids_size_) {
        const char* st = pDexFile->StringDataByIdx(dex::StringIndex(index));
        outSize = snprintf(buf.get(), bufSize, "\"%s\" // string@%0*x", st, width, index);
      } else {
        outSize = snprintf(buf.get(), bufSize, "<string?> // string@%0*x", width, index);
      }
      break;
    case Instruction::kIndexMethodRef:
      if (index < pDexFile->GetHeader().method_ids_size_) {
        const dex::MethodId& pMethodId = pDexFile->GetMethodId(index);
        const char* name = pDexFile->StringDataByIdx(pMethodId.name_idx_);
        const Signature signature = pDexFile->GetMethodSignature(pMethodId);
        const char* backDescriptor = pDexFile->StringByTypeIdx(pMethodId.class_idx_);
        outSize = snprintf(buf.get(), bufSize, "%s.%s:%s // method@%0*x",
                           backDescriptor, name, signature.ToString().c_str(), width, index);
      } else {
        outSize = snprintf(buf.get(), bufSize, "<method?> // method@%0*x", width, index);
      }
      break;
    case Instruction::kIndexFieldRef:
      if (index < pDexFile->GetHeader().field_ids_size_) {
        const dex::FieldId& pFieldId = pDexFile->GetFieldId(index);
        const char* name = pDexFile->StringDataByIdx(pFieldId.name_idx_);
        const char* typeDescriptor = pDexFile->StringByTypeIdx(pFieldId.type_idx_);
        const char* backDescriptor = pDexFile->StringByTypeIdx(pFieldId.class_idx_);
        outSize = snprintf(buf.get(), bufSize, "%s.%s:%s // field@%0*x",
                           backDescriptor, name, typeDescriptor, width, index);
      } else {
        outSize = snprintf(buf.get(), bufSize, "<field?> // field@%0*x", width, index);
      }
      break;
    case Instruction::kIndexVtableOffset:
      outSize = snprintf(buf.get(), bufSize, "[%0*x] // vtable #%0*x",
                         width, index, width, index);
      break;
    case Instruction::kIndexFieldOffset:
      outSize = snprintf(buf.get(), bufSize, "[obj+%0*x]", width, index);
      break;
    case Instruction::kIndexMethodAndProtoRef: {
      std::string method("<method?>");
      std::string proto("<proto?>");
      if (index < pDexFile->GetHeader().method_ids_size_) {
        const dex::MethodId& pMethodId = pDexFile->GetMethodId(index);
        const char* name = pDexFile->StringDataByIdx(pMethodId.name_idx_);
        const Signature signature = pDexFile->GetMethodSignature(pMethodId);
        const char* backDescriptor = pDexFile->StringByTypeIdx(pMethodId.class_idx_);
        method = android::base::StringPrintf("%s.%s:%s",
                                             backDescriptor,
                                             name,
                                             signature.ToString().c_str());
      }
      if (secondary_index < pDexFile->GetHeader().proto_ids_size_) {
        const dex::ProtoId& protoId = pDexFile->GetProtoId(dex::ProtoIndex(secondary_index));
        const Signature signature = pDexFile->GetProtoSignature(protoId);
        proto = signature.ToString();
      }
      outSize = snprintf(buf.get(), bufSize, "%s, %s // method@%0*x, proto@%0*x",
                         method.c_str(), proto.c_str(), width, index, width, secondary_index);
      break;
    }
    case Instruction::kIndexCallSiteRef:
      // Call site information is too large to detail in disassembly so just output the index.
      outSize = snprintf(buf.get(), bufSize, "call_site@%0*x", width, index);
      break;
    case Instruction::kIndexMethodHandleRef:
      // Method handle information is too large to detail in disassembly so just output the index.
      outSize = snprintf(buf.get(), bufSize, "method_handle@%0*x", width, index);
      break;
    case Instruction::kIndexProtoRef:
      if (index < pDexFile->GetHeader().proto_ids_size_) {
        const dex::ProtoId& protoId = pDexFile->GetProtoId(dex::ProtoIndex(index));
        const Signature signature = pDexFile->GetProtoSignature(protoId);
        const std::string& proto = signature.ToString();
        outSize = snprintf(buf.get(), bufSize, "%s // proto@%0*x", proto.c_str(), width, index);
      } else {
        outSize = snprintf(buf.get(), bufSize, "<?> // proto@%0*x", width, index);
      }
      break;
  }  // switch

  if (outSize == 0) {
    // The index type has not been handled in the switch above.
    outSize = snprintf(buf.get(), bufSize, "<?>");
  }

  // Determine success of string construction.
  if (outSize >= bufSize) {
    // The buffer wasn't big enough; retry with computed size. Note: snprintf()
    // doesn't count/ the '\0' as part of its returned size, so we add explicit
    // space for it here.
    return indexString(pDexFile, pDecInsn, outSize + 1);
  }
  return buf;
}


void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
                       const char* shorty) {
  if (UNLIKELY(__builtin_frame_address(0) < self->GetStackEnd())) {
    ThrowStackOverflowError(self);
    return;
  }

  std::ostringstream jweezy;
  

  if (kIsDebugBuild) {
    self->AssertThreadSuspensionIsAllowable();
    CHECK_EQ(kRunnable, self->GetState());
    CHECK_STREQ(GetInterfaceMethodIfProxy(kRuntimePointerSize)->GetShorty(), shorty);
  }

  // Push a transition back into managed code onto the linked list in thread.
  ManagedStack fragment;
  self->PushManagedStackFragment(&fragment);
  bool logged = false;
  Runtime* runtime = Runtime::Current();
  // Call the invoke stub, passing everything as arguments.
  // If the runtime is not yet started or it is required by the debugger, then perform the
  // Invocation by the interpreter, explicitly forcing interpretation over JIT to prevent
  // cycling around the various JIT/Interpreter methods that handle method invocation.
  if (UNLIKELY(!runtime->IsStarted() ||
               (self->IsForceInterpreter() && !IsNative() && !IsProxyMethod() && IsInvokable()))) {
    if (IsStatic()) {
      art::interpreter::EnterInterpreterFromInvoke(
          self, this, nullptr, args, result, /*stay_in_interpreter=*/ true);
    } else {
      mirror::Object* receiver =
          reinterpret_cast<StackReference<mirror::Object>*>(&args[0])->AsMirrorPtr();
      art::interpreter::EnterInterpreterFromInvoke(
          self, this, receiver, args + 1, result, /*stay_in_interpreter=*/ true);
    }
  } else {
    DCHECK_EQ(runtime->GetClassLinker()->GetImagePointerSize(), kRuntimePointerSize);

    constexpr bool kLogInvocationStartAndReturn = false;
    bool have_quick_code = GetEntryPointFromQuickCompiledCode() != nullptr;
    if (LIKELY(have_quick_code)) {
      if (kLogInvocationStartAndReturn) {
        LOG(INFO) << StringPrintf(
            "Invoking '%s' quick code=%p static=%d", PrettyMethod().c_str(),
            GetEntryPointFromQuickCompiledCode(), static_cast<int>(IsStatic() ? 1 : 0));
      }

      // Ensure that we won't be accidentally calling quick compiled code when -Xint.
      if (kIsDebugBuild && runtime->GetInstrumentation()->IsForcedInterpretOnly()) {
        CHECK(!runtime->UseJitCompilation());
        const void* oat_quick_code =
            (IsNative() || !IsInvokable() || IsProxyMethod() || IsObsolete())
            ? nullptr
            : GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize());
        CHECK(oat_quick_code == nullptr || oat_quick_code != GetEntryPointFromQuickCompiledCode())
            << "Don't call compiled code when -Xint " << PrettyMethod();
      }

      if (!IsStatic()) {
        logged = true;
        jweezy << "\tJACK LOG: INVOKING" << PrettyMethod() << "\tSHORTY: " << shorty << "\tArgs size: " << args_size << "\t";
        

        if(args_size > 0){
          capture_arguments(args,args_size,shorty, jweezy, !IsStatic());
        }


       
        (*art_quick_invoke_stub)(this, args, args_size, self, result, shorty);

        
        if (args_size > 0){
          
          char ret_typing = shorty[0];
          uint8_t z_ret;
          int8_t b_ret;
          uint16_t c_ret;
          int16_t s_ret;
          int32_t i_ret;
          int64_t j_ret;
          float f_ret;
          double d_ret;
          mirror::Object* l_ret;
          int BYTES_TO_PRINT = 500;

          switch(ret_typing){
            case 'B':{
              b_ret = result->GetB();
              jweezy << StringPrintf("\tRet: %d\t",b_ret);
              break;
            }
            case 'C':{
              c_ret = result->GetC();
              jweezy << StringPrintf("\tRet: %d\t",c_ret);
              break;
            }
            case 'D':{
              d_ret = result->GetD();
              jweezy << StringPrintf("\tRet: %lf\t",d_ret);
              break;
            }
            case 'F':{
              f_ret = result->GetF();
              jweezy << StringPrintf("\tRet: %f\t",f_ret);
              break;
            }
            case 'I':{
              i_ret = result->GetI();
              jweezy << StringPrintf("\tRet: %d\t",i_ret);
              break;
            }
            case 'J':{
              j_ret = result->GetJ();
              jweezy << StringPrintf("\tRet: %lx\t",(unsigned long)j_ret);
            
            break;
            }
            case 'L':{
              l_ret = result->GetL();
              jweezy << StringPrintf("\tRet: %p\t",l_ret);
              if(l_ret != nullptr && l_ret != 0){
                jweezy << "\tData at Ret:";

                BYTES_TO_PRINT = max_readable_bytes((void*)l_ret,BYTES_TO_PRINT);
                
                if(BYTES_TO_PRINT > 0){
                  for(int j =0; j < BYTES_TO_PRINT; j++){
                    jweezy << StringPrintf("%x ", ((char*)l_ret)[j] );//Log bytes at address
                  }
                  jweezy << "\t";
                }else{
                  jweezy << "\tEXECUTABLE ONLY(THIS IS WEIRD)\t";
                }
                
                }else{
                  jweezy << "\tAddress NULL\t";
                }
              break;
            }
            case 'S':{
              s_ret = result->GetS();
              jweezy << StringPrintf("\tRet: %d\t",s_ret);
              break;
            }
            case 'Z':{
              z_ret = result->GetZ();
              jweezy << StringPrintf("\tRet: %d\t",z_ret);
              break;
            }
          }

        }
        

        int length = jweezy.str().length();
        std::ostringstream ss;
        std::ostringstream header;
        int spacer = (5120-header.str().length());
        header << "JACK LOG: " << PrettyMethod() << " CONT.\t";
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



      } else {
        logged = true;
        jweezy << "\tJACK LOG: INVOKING" << PrettyMethod() << "\tSHORTY: " << shorty << "\tArgs size: " << args_size << "\t";
        
        
        //Recreating data extraction methods layed out in the quick_entrypoints_arm64.S
        //Position of shorty
        
        
        if(args_size > 0){
        capture_arguments(args,args_size,shorty, jweezy, !IsStatic());
        }
    

        (*art_quick_invoke_static_stub)(this, args, args_size, self, result, shorty);

       
        if (args_size > 0){
          char ret_typing = shorty[0];
          uint8_t z_ret;
          int8_t b_ret;
          uint16_t c_ret;
          int16_t s_ret;
          int32_t i_ret;
          int64_t j_ret;
          float f_ret;
          double d_ret;
          mirror::Object* l_ret;
          int BYTES_TO_PRINT = 500;

          switch(ret_typing){
            case 'B':{
              b_ret = result->GetB();
              jweezy << StringPrintf("\tRet: %d\t",b_ret);
              break;
            }
            case 'C':{
              c_ret = result->GetC();
              jweezy << StringPrintf("\tRet: %d\t",c_ret);
              break;
            }
            case 'D':{
              d_ret = result->GetD();
              jweezy << StringPrintf("\tRet: %lf\t",d_ret);
              break;
            }
            case 'F':{
              f_ret = result->GetF();
              jweezy << StringPrintf("\tRet: %f\t",f_ret);
              break;
            }
            case 'I':{
              i_ret = result->GetI();
              jweezy << StringPrintf("\tRet: %d\t",i_ret);
              break;
            }
            case 'J':{
              j_ret = result->GetJ();
              jweezy << StringPrintf("\tRet: %lx\t",(unsigned long)j_ret);
            
            break;
            }
            case 'L':{
              l_ret = result->GetL();
              jweezy << StringPrintf("\tRet: %p\t",l_ret);
              if(l_ret != nullptr && l_ret != 0){
                jweezy << "\tData at Ret:";

                BYTES_TO_PRINT = max_readable_bytes((void*)l_ret,BYTES_TO_PRINT);
                
                if(BYTES_TO_PRINT > 0){
                  for(int j =0; j < BYTES_TO_PRINT; j++){
                    jweezy << StringPrintf("%x ", ((char*)l_ret)[j] );//Log bytes at address
                  }
                  jweezy << "\t";
                }else{
                  jweezy << "\tEXECUTABLE ONLY(THIS IS WEIRD)\t";
                }
                
                }else{
                  jweezy << "\tAddress NULL\t";
                }
              break;
            }
            case 'S':{
              s_ret = result->GetS();
              jweezy << StringPrintf("\tRet: %d\t",s_ret);
              break;
            }
            case 'Z':{
              z_ret = result->GetZ();
              jweezy << StringPrintf("\tRet: %d\t",z_ret);
              break;
            }
          }
        }
        



        int length = jweezy.str().length();
        std::ostringstream ss;
        std::ostringstream header;
        int spacer = (5120-header.str().length());
        header << "JACK LOG: " << PrettyMethod() << " CONT.\t";
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
      if (UNLIKELY(self->GetException() == Thread::GetDeoptimizationException())) {
        // Unusual case where we were running generated code and an
        // exception was thrown to force the activations to be removed from the
        // stack. Continue execution in the interpreter.
        self->DeoptimizeWithDeoptimizationException(result);
      }
      if (kLogInvocationStartAndReturn) {
        LOG(INFO) << StringPrintf("Returned '%s' quick code=%p", PrettyMethod().c_str(),
                                  GetEntryPointFromQuickCompiledCode());
      }
    } else {
      LOG(INFO) << "Not invoking '" << PrettyMethod() << "' code=null";
      if (result != nullptr) {
        result->SetJ(0);
      }
    }
  }

  
  jweezy.str("");
  
  if(logged==false){
    jweezy << "\tJACK LOG: NON CAUGHT METHOD" << PrettyMethod() << "\tSHORTY: " << shorty << "\tArgs size: " << args_size << "\t";
    LOG(INFO) << jweezy.str();
    jweezy.str("");
  }

  bool log_dis = false;

  if (log_dis){
    CodeItemInstructionAccessor a =  DexInstructions();
    const DexFile* df = GetDexFile();

    // Op Code Parser
    CodeItemInstructionAccessor tmp_weezy = a;
    if (tmp_weezy.Insns() != nullptr){
      using u1 = uint8_t;
      using u2 = uint16_t;
      using u4 = uint32_t;
      using u8 = uint64_t;
      using s4 = int32_t;
      using s8 = int64_t;

      jweezy << PrettyMethod() << "\t" << StringPrintf("JACK BYTECODE LOG:\t");
      // int size = tmp_weezy.end() - tmp_weezy.begin();
      const u4 maxPc = tmp_weezy.InsnsSizeInCodeUnits();
      for (const DexInstructionPcPair& pair : tmp_weezy) {
        const u4 dexPc = pair.DexPc();

        if (dexPc >= maxPc) {
        break;
      }

        const Instruction* instruction = &pair.Inst();
        const u4 insnWidth = instruction->SizeInCodeUnits();

        if (insnWidth == 0) {
        break;
      }

          if (instruction->Opcode() == Instruction::NOP) {
            const u1* pSrc = (const u1*) &tmp_weezy.Insns()[dexPc];
            const u2 instr = pSrc[0] | (pSrc[1] << 8);
            if (instr == Instruction::kPackedSwitchSignature) {
              jweezy << StringPrintf("|%04x: packed-switch-data (%d units)", dexPc, insnWidth);
            } else if (instr == Instruction::kSparseSwitchSignature) {
              jweezy << StringPrintf( "|%04x: sparse-switch-data (%d units)", dexPc, insnWidth);
            } else if (instr == Instruction::kArrayDataSignature) {
              jweezy << StringPrintf("|%04x: array-data (%d units)", dexPc, insnWidth);
            } else {
              jweezy << StringPrintf( "|%04x: nop // spacer", dexPc);
            }
          } else {
            jweezy << StringPrintf("|%04x: %s", dexPc, instruction->Name());
          }

        std::unique_ptr<char[]> indexBuf;
        if (Instruction::IndexTypeOf(instruction->Opcode()) != Instruction::kIndexNone) {
          indexBuf = indexString(df, instruction, 200);
        }

        // Dump the instruction.
    //
    // NOTE: instruction->DumpString(pDexFile) differs too much from original.
    //
    switch (Instruction::FormatOf(instruction->Opcode())) {
      case Instruction::k10x:        // op
        break;
      case Instruction::k12x:        // op vA, vB
        jweezy << StringPrintf( " v%d, v%d", instruction->VRegA(), instruction->VRegB());
        break;
      case Instruction::k11n:        // op vA, #+B
        jweezy << StringPrintf( " v%d, #int %d // #%x",
                instruction->VRegA(), (s4) instruction->VRegB(), (u1)instruction->VRegB());
        break;
      case Instruction::k11x:        // op vAA
        jweezy << StringPrintf( " v%d", instruction->VRegA());
        break;
      case Instruction::k10t:        // op +AA
      case Instruction::k20t: {      // op +AAAA
        const s4 targ = (s4) instruction->VRegA();
        jweezy << StringPrintf( " %04x // %c%04x",
                dexPc + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        break;
      }
      case Instruction::k22x:        // op vAA, vBBBB
        jweezy << StringPrintf( " v%d, v%d", instruction->VRegA(), instruction->VRegB());
        break;
      case Instruction::k21t: {     // op vAA, +BBBB
        const s4 targ = (s4) instruction->VRegB();
        jweezy << StringPrintf( " v%d, %04x // %c%04x", instruction->VRegA(),
                dexPc + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        break;
      }
      case Instruction::k21s:        // op vAA, #+BBBB
        jweezy << StringPrintf( " v%d, #int %d // #%x",
                instruction->VRegA(), (s4) instruction->VRegB(), (u2)instruction->VRegB());
        break;
      case Instruction::k21h:        // op vAA, #+BBBB0000[00000000]
        // The printed format varies a bit based on the actual opcode.
        if (instruction->Opcode() == Instruction::CONST_HIGH16) {
          const s4 value = instruction->VRegB() << 16;
          jweezy << StringPrintf( " v%d, #int %d // #%x",
                  instruction->VRegA(), value, (u2) instruction->VRegB());
        } else {
          const s8 value = ((s8) instruction->VRegB()) << 48;
          jweezy << StringPrintf( " v%d, #long %" PRId64 " // #%x",
                  instruction->VRegA(), value, (u2) instruction->VRegB());
        }
        break;
      case Instruction::k21c:        // op vAA, thing@BBBB
      case Instruction::k31c:        // op vAA, thing@BBBBBBBB
        jweezy << StringPrintf( " v%d, %s", instruction->VRegA(), indexBuf.get());
        break;
      case Instruction::k23x:        // op vAA, vBB, vCC
        jweezy << StringPrintf( " v%d, v%d, v%d",
                instruction->VRegA(), instruction->VRegB(), instruction->VRegC());
        break;
      case Instruction::k22b:        // op vAA, vBB, #+CC
        jweezy << StringPrintf( " v%d, v%d, #int %d // #%02x",
                instruction->VRegA(), instruction->VRegB(),
                (s4) instruction->VRegC(), (u1) instruction->VRegC());
        break;
      case Instruction::k22t: {      // op vA, vB, +CCCC
        const s4 targ = (s4) instruction->VRegC();
        jweezy << StringPrintf( " v%d, v%d, %04x // %c%04x",
                instruction->VRegA(), instruction->VRegB(),
                dexPc + targ,
                (targ < 0) ? '-' : '+',
                (targ < 0) ? -targ : targ);
        break;
      }
      case Instruction::k22s:        // op vA, vB, #+CCCC
        jweezy << StringPrintf( " v%d, v%d, #int %d // #%04x",
                instruction->VRegA(), instruction->VRegB(),
                (s4) instruction->VRegC(), (u2) instruction->VRegC());
        break;
      case Instruction::k22c:        // op vA, vB, thing@CCCC
      // NOT SUPPORTED:
      // case Instruction::k22cs:    // [opt] op vA, vB, field offset CCCC
        jweezy << StringPrintf( " v%d, v%d, %s",
                instruction->VRegA(), instruction->VRegB(), indexBuf.get());
        break;
      case Instruction::k30t:
        jweezy << StringPrintf( " #%08x", instruction->VRegA());
        break;
      case Instruction::k31i: {     // op vAA, #+BBBBBBBB
        // This is often, but not always, a float.
        union {
          float f;
          u4 i;
        } conv;
        conv.i = instruction->VRegB();
        jweezy << StringPrintf( " v%d, #float %g // #%08x",
                instruction->VRegA(), conv.f, instruction->VRegB());
        break;
      }
      case Instruction::k31t:       // op vAA, offset +BBBBBBBB
        jweezy << StringPrintf( " v%d, %08x // +%08x",
                instruction->VRegA(), dexPc + instruction->VRegB(), instruction->VRegB());
        break;
      case Instruction::k32x:        // op vAAAA, vBBBB
        jweezy << StringPrintf( " v%d, v%d", instruction->VRegA(), instruction->VRegB());
        break;
      case Instruction::k35c:       // op {vC, vD, vE, vF, vG}, thing@BBBB
      case Instruction::k45cc: {    // op {vC, vD, vE, vF, vG}, method@BBBB, proto@HHHH
      // NOT SUPPORTED:
      // case Instruction::k35ms:       // [opt] invoke-virtual+super
      // case Instruction::k35mi:       // [opt] inline invoke
        u4 arg[Instruction::kMaxVarArgRegs];
        instruction->GetVarArgs(arg);
        jweezy << " {";
        for (int i = 0, n = instruction->VRegA(); i < n; i++) {
          if (i == 0) {
            jweezy << StringPrintf( "v%d", arg[i]);
          } else {
            jweezy << StringPrintf( ", v%d", arg[i]);
          }
        }  // for
        jweezy << StringPrintf( "}, %s", indexBuf.get());
        break;
      }
      case Instruction::k3rc:        // op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
      case Instruction::k4rcc: {     // op {vCCCC .. v(CCCC+AA-1)}, method@BBBB, proto@HHHH
      // NOT SUPPORTED:
      // case Instruction::k3rms:       // [opt] invoke-virtual+super/range
      // case Instruction::k3rmi:       // [opt] execute-inline/range
          // This doesn't match the "dx" output when some of the args are
          // 64-bit values -- dx only shows the first register.
          jweezy << " {";
          for (int i = 0, n = instruction->VRegA(); i < n; i++) {
            if (i == 0) {
              jweezy << StringPrintf( "v%d", instruction->VRegC() + i);
            } else {
              jweezy << StringPrintf( ", v%d", instruction->VRegC() + i);
            }
          }  // for
          jweezy << StringPrintf( "}, %s", indexBuf.get());
        }
        break;
      case Instruction::k51l: {      // op vAA, #+BBBBBBBBBBBBBBBB
        // This is often, but not always, a double.
        union {
          double d;
          u8 j;
        } conv;
        conv.j = instruction->WideVRegB();
        jweezy << StringPrintf( " v%d, #double %g // #%016" PRIx64,
                instruction->VRegA(), conv.d, instruction->WideVRegB());
        break;
      }
      // NOT SUPPORTED:
      // case Instruction::k00x:        // unknown op or breakpoint
      //    break;
      default:
        jweezy << StringPrintf( " ???");
        break;
    }  // switch


      }

    

    int length = jweezy.str().length();
      std::ostringstream ss;
      std::ostringstream header;
      int spacer = (5120-header.str().length());
      header << "JACK BYTECODE LOG: " << PrettyMethod() << " CONT.\t";
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

    jweezy.str("");
  }
  

  // Pop transition.
  self->PopManagedStackFragment(fragment);
}

bool ArtMethod::IsOverridableByDefaultMethod() {
  return GetDeclaringClass()->IsInterface();
}

bool ArtMethod::IsSignaturePolymorphic() {
  // Methods with a polymorphic signature have constraints that they
  // are native and varargs and belong to either MethodHandle or VarHandle.
  if (!IsNative() || !IsVarargs()) {
    return false;
  }
  ObjPtr<mirror::ObjectArray<mirror::Class>> class_roots =
      Runtime::Current()->GetClassLinker()->GetClassRoots();
  ObjPtr<mirror::Class> cls = GetDeclaringClass();
  return (cls == GetClassRoot<mirror::MethodHandle>(class_roots) ||
          cls == GetClassRoot<mirror::VarHandle>(class_roots));
}

static uint32_t GetOatMethodIndexFromMethodIndex(const DexFile& dex_file,
                                                 uint16_t class_def_idx,
                                                 uint32_t method_idx) {
  ClassAccessor accessor(dex_file, class_def_idx);
  uint32_t class_def_method_index = 0u;
  for (const ClassAccessor::Method& method : accessor.GetMethods()) {
    if (method.GetIndex() == method_idx) {
      return class_def_method_index;
    }
    class_def_method_index++;
  }
  LOG(FATAL) << "Failed to find method index " << method_idx << " in " << dex_file.GetLocation();
  UNREACHABLE();
}

// We use the method's DexFile and declaring class name to find the OatMethod for an obsolete
// method.  This is extremely slow but we need it if we want to be able to have obsolete native
// methods since we need this to find the size of its stack frames.
//
// NB We could (potentially) do this differently and rely on the way the transformation is applied
// in order to use the entrypoint to find this information. However, for debugging reasons (most
// notably making sure that new invokes of obsolete methods fail) we choose to instead get the data
// directly from the dex file.
static const OatFile::OatMethod FindOatMethodFromDexFileFor(ArtMethod* method, bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  DCHECK(method->IsObsolete() && method->IsNative());
  const DexFile* dex_file = method->GetDexFile();

  // recreate the class_def_index from the descriptor.
  std::string descriptor_storage;
  const dex::TypeId* declaring_class_type_id =
      dex_file->FindTypeId(method->GetDeclaringClass()->GetDescriptor(&descriptor_storage));
  CHECK(declaring_class_type_id != nullptr);
  dex::TypeIndex declaring_class_type_index = dex_file->GetIndexForTypeId(*declaring_class_type_id);
  const dex::ClassDef* declaring_class_type_def =
      dex_file->FindClassDef(declaring_class_type_index);
  CHECK(declaring_class_type_def != nullptr);
  uint16_t declaring_class_def_index = dex_file->GetIndexForClassDef(*declaring_class_type_def);

  size_t oat_method_index = GetOatMethodIndexFromMethodIndex(*dex_file,
                                                             declaring_class_def_index,
                                                             method->GetDexMethodIndex());

  OatFile::OatClass oat_class = OatFile::FindOatClass(*dex_file,
                                                      declaring_class_def_index,
                                                      found);
  if (!(*found)) {
    return OatFile::OatMethod::Invalid();
  }
  return oat_class.GetOatMethod(oat_method_index);
}

static const OatFile::OatMethod FindOatMethodFor(ArtMethod* method,
                                                 PointerSize pointer_size,
                                                 bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  if (UNLIKELY(method->IsObsolete())) {
    // We shouldn't be calling this with obsolete methods except for native obsolete methods for
    // which we need to use the oat method to figure out how large the quick frame is.
    DCHECK(method->IsNative()) << "We should only be finding the OatMethod of obsolete methods in "
                               << "order to allow stack walking. Other obsolete methods should "
                               << "never need to access this information.";
    DCHECK_EQ(pointer_size, kRuntimePointerSize) << "Obsolete method in compiler!";
    return FindOatMethodFromDexFileFor(method, found);
  }
  // Although we overwrite the trampoline of non-static methods, we may get here via the resolution
  // method for direct methods (or virtual methods made direct).
  ObjPtr<mirror::Class> declaring_class = method->GetDeclaringClass();
  size_t oat_method_index;
  if (method->IsStatic() || method->IsDirect()) {
    // Simple case where the oat method index was stashed at load time.
    oat_method_index = method->GetMethodIndex();
  } else {
    // Compute the oat_method_index by search for its position in the declared virtual methods.
    oat_method_index = declaring_class->NumDirectMethods();
    bool found_virtual = false;
    for (ArtMethod& art_method : declaring_class->GetVirtualMethods(pointer_size)) {
      // Check method index instead of identity in case of duplicate method definitions.
      if (method->GetDexMethodIndex() == art_method.GetDexMethodIndex()) {
        found_virtual = true;
        break;
      }
      oat_method_index++;
    }
    CHECK(found_virtual) << "Didn't find oat method index for virtual method: "
                         << method->PrettyMethod();
  }
  DCHECK_EQ(oat_method_index,
            GetOatMethodIndexFromMethodIndex(declaring_class->GetDexFile(),
                                             method->GetDeclaringClass()->GetDexClassDefIndex(),
                                             method->GetDexMethodIndex()));
  OatFile::OatClass oat_class = OatFile::FindOatClass(declaring_class->GetDexFile(),
                                                      declaring_class->GetDexClassDefIndex(),
                                                      found);
  if (!(*found)) {
    return OatFile::OatMethod::Invalid();
  }
  return oat_class.GetOatMethod(oat_method_index);
}

bool ArtMethod::EqualParameters(Handle<mirror::ObjectArray<mirror::Class>> params) {
  const DexFile* dex_file = GetDexFile();
  const auto& method_id = dex_file->GetMethodId(GetDexMethodIndex());
  const auto& proto_id = dex_file->GetMethodPrototype(method_id);
  const dex::TypeList* proto_params = dex_file->GetProtoParameters(proto_id);
  auto count = proto_params != nullptr ? proto_params->Size() : 0u;
  auto param_len = params != nullptr ? params->GetLength() : 0u;
  if (param_len != count) {
    return false;
  }
  auto* cl = Runtime::Current()->GetClassLinker();
  for (size_t i = 0; i < count; ++i) {
    dex::TypeIndex type_idx = proto_params->GetTypeItem(i).type_idx_;
    ObjPtr<mirror::Class> type = cl->ResolveType(type_idx, this);
    if (type == nullptr) {
      Thread::Current()->AssertPendingException();
      return false;
    }
    if (type != params->GetWithoutChecks(i)) {
      return false;
    }
  }
  return true;
}

const OatQuickMethodHeader* ArtMethod::GetOatQuickMethodHeader(uintptr_t pc) {
  // Our callers should make sure they don't pass the instrumentation exit pc,
  // as this method does not look at the side instrumentation stack.
  DCHECK_NE(pc, reinterpret_cast<uintptr_t>(GetQuickInstrumentationExitPc()));

  if (IsRuntimeMethod()) {
    return nullptr;
  }

  Runtime* runtime = Runtime::Current();
  const void* existing_entry_point = GetEntryPointFromQuickCompiledCode();
  CHECK(existing_entry_point != nullptr) << PrettyMethod() << "@" << this;
  ClassLinker* class_linker = runtime->GetClassLinker();

  if (existing_entry_point == GetQuickProxyInvokeHandler()) {
    DCHECK(IsProxyMethod() && !IsConstructor());
    // The proxy entry point does not have any method header.
    return nullptr;
  }

  // Check whether the current entry point contains this pc.
  if (!class_linker->IsQuickGenericJniStub(existing_entry_point) &&
      !class_linker->IsQuickResolutionStub(existing_entry_point) &&
      !class_linker->IsQuickToInterpreterBridge(existing_entry_point) &&
      existing_entry_point != GetQuickInstrumentationEntryPoint()) {
    OatQuickMethodHeader* method_header =
        OatQuickMethodHeader::FromEntryPoint(existing_entry_point);

    if (method_header->Contains(pc)) {
      return method_header;
    }
  }

  if (OatQuickMethodHeader::NterpMethodHeader != nullptr &&
      OatQuickMethodHeader::NterpMethodHeader->Contains(pc)) {
    return OatQuickMethodHeader::NterpMethodHeader;
  }

  // Check whether the pc is in the JIT code cache.
  jit::Jit* jit = runtime->GetJit();
  if (jit != nullptr) {
    jit::JitCodeCache* code_cache = jit->GetCodeCache();
    OatQuickMethodHeader* method_header = code_cache->LookupMethodHeader(pc, this);
    if (method_header != nullptr) {
      DCHECK(method_header->Contains(pc));
      return method_header;
    } else {
      DCHECK(!code_cache->ContainsPc(reinterpret_cast<const void*>(pc)))
          << PrettyMethod()
          << ", pc=" << std::hex << pc
          << ", entry_point=" << std::hex << reinterpret_cast<uintptr_t>(existing_entry_point)
          << ", copy=" << std::boolalpha << IsCopied()
          << ", proxy=" << std::boolalpha << IsProxyMethod();
    }
  }

  // The code has to be in an oat file.
  bool found;
  OatFile::OatMethod oat_method =
      FindOatMethodFor(this, class_linker->GetImagePointerSize(), &found);
  if (!found) {
    if (IsNative()) {
      // We are running the GenericJNI stub. The entrypoint may point
      // to different entrypoints or to a JIT-compiled JNI stub.
      DCHECK(class_linker->IsQuickGenericJniStub(existing_entry_point) ||
             class_linker->IsQuickResolutionStub(existing_entry_point) ||
             existing_entry_point == GetQuickInstrumentationEntryPoint() ||
             (jit != nullptr && jit->GetCodeCache()->ContainsPc(existing_entry_point)))
          << " entrypoint: " << existing_entry_point
          << " size: " << OatQuickMethodHeader::FromEntryPoint(existing_entry_point)->GetCodeSize()
          << " pc: " << reinterpret_cast<const void*>(pc);
      return nullptr;
    }
    // Only for unit tests.
    // TODO(ngeoffray): Update these tests to pass the right pc?
    return OatQuickMethodHeader::FromEntryPoint(existing_entry_point);
  }
  const void* oat_entry_point = oat_method.GetQuickCode();
  if (oat_entry_point == nullptr || class_linker->IsQuickGenericJniStub(oat_entry_point)) {
    DCHECK(IsNative()) << PrettyMethod();
    return nullptr;
  }

  OatQuickMethodHeader* method_header = OatQuickMethodHeader::FromEntryPoint(oat_entry_point);
  if (pc == 0) {
    // This is a downcall, it can only happen for a native method.
    DCHECK(IsNative());
    return method_header;
  }

  DCHECK(method_header->Contains(pc))
      << PrettyMethod()
      << " " << std::hex << pc << " " << oat_entry_point
      << " " << (uintptr_t)(method_header->GetCode() + method_header->GetCodeSize());
  return method_header;
}

const void* ArtMethod::GetOatMethodQuickCode(PointerSize pointer_size) {
  bool found;
  OatFile::OatMethod oat_method = FindOatMethodFor(this, pointer_size, &found);
  if (found) {
    return oat_method.GetQuickCode();
  }
  return nullptr;
}

bool ArtMethod::HasAnyCompiledCode() {
  if (IsNative() || !IsInvokable() || IsProxyMethod()) {
    return false;
  }

  // Check whether the JIT has compiled it.
  Runtime* runtime = Runtime::Current();
  jit::Jit* jit = runtime->GetJit();
  if (jit != nullptr && jit->GetCodeCache()->ContainsMethod(this)) {
    return true;
  }

  // Check whether we have AOT code.
  return GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize()) != nullptr;
}

void ArtMethod::SetIntrinsic(uint32_t intrinsic) {
  // Currently we only do intrinsics for static/final methods or methods of final
  // classes. We don't set kHasSingleImplementation for those methods.
  DCHECK(IsStatic() || IsFinal() || GetDeclaringClass()->IsFinal()) <<
      "Potential conflict with kAccSingleImplementation";
  static const int kAccFlagsShift = CTZ(kAccIntrinsicBits);
  DCHECK_LE(intrinsic, kAccIntrinsicBits >> kAccFlagsShift);
  uint32_t intrinsic_bits = intrinsic << kAccFlagsShift;
  uint32_t new_value = (GetAccessFlags() & ~kAccIntrinsicBits) | kAccIntrinsic | intrinsic_bits;
  if (kIsDebugBuild) {
    uint32_t java_flags = (GetAccessFlags() & kAccJavaFlagsMask);
    bool is_constructor = IsConstructor();
    bool is_synchronized = IsSynchronized();
    bool skip_access_checks = SkipAccessChecks();
    bool is_fast_native = IsFastNative();
    bool is_critical_native = IsCriticalNative();
    bool is_copied = IsCopied();
    bool is_miranda = IsMiranda();
    bool is_default = IsDefault();
    bool is_default_conflict = IsDefaultConflicting();
    bool is_compilable = IsCompilable();
    bool must_count_locks = MustCountLocks();
    // Recompute flags instead of getting them from the current access flags because
    // access flags may have been changed to deduplicate warning messages (b/129063331).
    uint32_t hiddenapi_flags = hiddenapi::CreateRuntimeFlags(this);
    SetAccessFlags(new_value);
    DCHECK_EQ(java_flags, (GetAccessFlags() & kAccJavaFlagsMask));
    DCHECK_EQ(is_constructor, IsConstructor());
    DCHECK_EQ(is_synchronized, IsSynchronized());
    DCHECK_EQ(skip_access_checks, SkipAccessChecks());
    DCHECK_EQ(is_fast_native, IsFastNative());
    DCHECK_EQ(is_critical_native, IsCriticalNative());
    DCHECK_EQ(is_copied, IsCopied());
    DCHECK_EQ(is_miranda, IsMiranda());
    DCHECK_EQ(is_default, IsDefault());
    DCHECK_EQ(is_default_conflict, IsDefaultConflicting());
    DCHECK_EQ(is_compilable, IsCompilable());
    DCHECK_EQ(must_count_locks, MustCountLocks());
    // Only DCHECK that we have preserved the hidden API access flags if the
    // original method was not on the whitelist. This is because the core image
    // does not have the access flags set (b/77733081).
    if ((hiddenapi_flags & kAccHiddenapiBits) != kAccPublicApi) {
      DCHECK_EQ(hiddenapi_flags, hiddenapi::GetRuntimeFlags(this)) << PrettyMethod();
    }
  } else {
    SetAccessFlags(new_value);
  }
}

void ArtMethod::SetNotIntrinsic() {
  if (!IsIntrinsic()) {
    return;
  }

  // Read the existing hiddenapi flags.
  uint32_t hiddenapi_runtime_flags = hiddenapi::GetRuntimeFlags(this);

  // Clear intrinsic-related access flags.
  ClearAccessFlags(kAccIntrinsic | kAccIntrinsicBits);

  // Re-apply hidden API access flags now that the method is not an intrinsic.
  SetAccessFlags(GetAccessFlags() | hiddenapi_runtime_flags);
  DCHECK_EQ(hiddenapi_runtime_flags, hiddenapi::GetRuntimeFlags(this));
}

void ArtMethod::CopyFrom(ArtMethod* src, PointerSize image_pointer_size) {
  memcpy(reinterpret_cast<void*>(this), reinterpret_cast<const void*>(src),
         Size(image_pointer_size));
  declaring_class_ = GcRoot<mirror::Class>(const_cast<ArtMethod*>(src)->GetDeclaringClass());

  // If the entry point of the method we are copying from is from JIT code, we just
  // put the entry point of the new method to interpreter or GenericJNI. We could set
  // the entry point to the JIT code, but this would require taking the JIT code cache
  // lock to notify it, which we do not want at this level.
  Runtime* runtime = Runtime::Current();
  if (runtime->UseJitCompilation()) {
    if (runtime->GetJit()->GetCodeCache()->ContainsPc(GetEntryPointFromQuickCompiledCode())) {
      SetEntryPointFromQuickCompiledCodePtrSize(
          src->IsNative() ? GetQuickGenericJniStub() : GetQuickToInterpreterBridge(),
          image_pointer_size);
    }
  }
  if (interpreter::IsNterpSupported() &&
      (GetEntryPointFromQuickCompiledCodePtrSize(image_pointer_size) ==
          interpreter::GetNterpEntryPoint())) {
    // If the entrypoint is nterp, it's too early to check if the new method
    // will support it. So for simplicity, use the interpreter bridge.
    SetEntryPointFromQuickCompiledCodePtrSize(GetQuickToInterpreterBridge(), image_pointer_size);
  }

  // Clear the data pointer, it will be set if needed by the caller.
  if (!src->HasCodeItem() && !src->IsNative()) {
    SetDataPtrSize(nullptr, image_pointer_size);
  }
  // Clear hotness to let the JIT properly decide when to compile this method.
  hotness_count_ = 0;
}

bool ArtMethod::IsImagePointerSize(PointerSize pointer_size) {
  // Hijack this function to get access to PtrSizedFieldsOffset.
  //
  // Ensure that PrtSizedFieldsOffset is correct. We rely here on usually having both 32-bit and
  // 64-bit builds.
  static_assert(std::is_standard_layout<ArtMethod>::value, "ArtMethod is not standard layout.");
  static_assert(
      (sizeof(void*) != 4) ||
          (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k32)),
      "Unexpected 32-bit class layout.");
  static_assert(
      (sizeof(void*) != 8) ||
          (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k64)),
      "Unexpected 64-bit class layout.");

  Runtime* runtime = Runtime::Current();
  if (runtime == nullptr) {
    return true;
  }
  return runtime->GetClassLinker()->GetImagePointerSize() == pointer_size;
}

std::string ArtMethod::PrettyMethod(ArtMethod* m, bool with_signature) {
  if (m == nullptr) {
    return "null";
  }
  return m->PrettyMethod(with_signature);
}

std::string ArtMethod::PrettyMethod(bool with_signature) {
  if (UNLIKELY(IsRuntimeMethod())) {
    std::string result = GetDeclaringClassDescriptor();
    result += '.';
    result += GetName();
    // Do not add "<no signature>" even if `with_signature` is true.
    return result;
  }
  ArtMethod* m =
      GetInterfaceMethodIfProxy(Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  std::string res(m->GetDexFile()->PrettyMethod(m->GetDexMethodIndex(), with_signature));
  if (with_signature && m->IsObsolete()) {
    return "<OBSOLETE> " + res;
  } else {
    return res;
  }
}

std::string ArtMethod::JniShortName() {
  return GetJniShortName(GetDeclaringClassDescriptor(), GetName());
}

std::string ArtMethod::JniLongName() {
  std::string long_name;
  long_name += JniShortName();
  long_name += "__";

  std::string signature(GetSignature().ToString());
  signature.erase(0, 1);
  signature.erase(signature.begin() + signature.find(')'), signature.end());

  long_name += MangleForJni(signature);

  return long_name;
}

const char* ArtMethod::GetRuntimeMethodName() {
  Runtime* const runtime = Runtime::Current();
  if (this == runtime->GetResolutionMethod()) {
    return "<runtime internal resolution method>";
  } else if (this == runtime->GetImtConflictMethod()) {
    return "<runtime internal imt conflict method>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveAllCalleeSaves)) {
    return "<runtime internal callee-save all registers method>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveRefsOnly)) {
    return "<runtime internal callee-save reference registers method>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveRefsAndArgs)) {
    return "<runtime internal callee-save reference and argument registers method>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverything)) {
    return "<runtime internal save-every-register method>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverythingForClinit)) {
    return "<runtime internal save-every-register method for clinit>";
  } else if (this == runtime->GetCalleeSaveMethod(CalleeSaveType::kSaveEverythingForSuspendCheck)) {
    return "<runtime internal save-every-register method for suspend check>";
  } else {
    return "<unknown runtime internal method>";
  }
}

void ArtMethod::SetCodeItem(const dex::CodeItem* code_item) {
  DCHECK(HasCodeItem());
  // We mark the lowest bit for the interpreter to know whether it's executing a
  // method in a compact or standard dex file.
  uintptr_t data =
      reinterpret_cast<uintptr_t>(code_item) | (GetDexFile()->IsCompactDexFile() ? 1 : 0);
  SetDataPtrSize(reinterpret_cast<void*>(data), kRuntimePointerSize);
}

// AssertSharedHeld doesn't work in GetAccessFlags, so use a NO_THREAD_SAFETY_ANALYSIS helper.
// TODO: Figure out why ASSERT_SHARED_CAPABILITY doesn't work.
template <ReadBarrierOption kReadBarrierOption>
ALWAYS_INLINE static inline void DoGetAccessFlagsHelper(ArtMethod* method)
    NO_THREAD_SAFETY_ANALYSIS {
  CHECK(method->IsRuntimeMethod() ||
        method->GetDeclaringClass<kReadBarrierOption>()->IsIdxLoaded() ||
        method->GetDeclaringClass<kReadBarrierOption>()->IsErroneous());
}

}  // namespace art
