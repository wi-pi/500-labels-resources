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

#ifndef ART_RUNTIME_INDIRECT_REFERENCE_TABLE_INL_H_
#define ART_RUNTIME_INDIRECT_REFERENCE_TABLE_INL_H_

#include "indirect_reference_table.h"
#include <fstream>

#include "android-base/stringprintf.h"

#include "base/dumpable.h"
#include "gc_root-inl.h"
#include "obj_ptr-inl.h"
#include "verify_object.h"

namespace art {
namespace mirror {
class Object;
}  // namespace mirror

// Verifies that the indirect table lookup is valid.
// Returns "false" if something looks bad.
inline bool IndirectReferenceTable::IsValidReference(IndirectRef iref,
                                                     /*out*/std::string* error_msg) const {
  DCHECK(iref != nullptr);
  DCHECK_EQ(GetIndirectRefKind(iref), kind_);
  const uint32_t top_index = segment_state_.top_index;
  uint32_t idx = ExtractIndex(iref);
  if (UNLIKELY(idx >= top_index)) {
    *error_msg = android::base::StringPrintf("deleted reference at index %u in a table of size %u",
                                             idx,
                                             top_index);
    return false;
  }
  if (UNLIKELY(table_[idx].GetReference()->IsNull())) {
    *error_msg = android::base::StringPrintf("deleted reference at index %u", idx);
    return false;
  }
  uint32_t iref_serial = DecodeSerial(reinterpret_cast<uintptr_t>(iref));
  uint32_t entry_serial = table_[idx].GetSerial();
  if (UNLIKELY(iref_serial != entry_serial)) {
    *error_msg = android::base::StringPrintf("stale reference with serial number %u v. current %u",
                                             iref_serial,
                                             entry_serial);
    return false;
  }
  return true;
}

// Make sure that the entry at "idx" is correctly paired with "iref".
inline bool IndirectReferenceTable::CheckEntry(const char* what,
                                               IndirectRef iref,
                                               uint32_t idx) const {
  IndirectRef checkRef = ToIndirectRef(idx);
  if (UNLIKELY(checkRef != iref)) {
    std::string msg = android::base::StringPrintf(
        "JNI ERROR (app bug): attempt to %s stale %s %p (should be %p)",
        what,
        GetIndirectRefKindString(kind_),
        iref,
        checkRef);
    AbortIfNoCheckJNI(msg);
    return false;
  }
  return true;
}

inline int max_readable_bytes4(void *ptr,int max) {
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



template<ReadBarrierOption kReadBarrierOption>
inline ObjPtr<mirror::Object> IndirectReferenceTable::Get(IndirectRef iref) const {
  DCHECK_EQ(GetIndirectRefKind(iref), kind_);
  uint32_t idx = ExtractIndex(iref);
  DCHECK_LT(idx, segment_state_.top_index);
  DCHECK_EQ(DecodeSerial(reinterpret_cast<uintptr_t>(iref)), table_[idx].GetSerial());
  DCHECK(!table_[idx].GetReference()->IsNull());
  ObjPtr<mirror::Object> obj = table_[idx].GetReference()->Read<kReadBarrierOption>();
  VerifyObject(obj);

  #ifdef __deez__
  int BYTES_TO_PRINT = 500;
  

  std::ostringstream jweezy;
  void* holder = obj.Ptr();

  BYTES_TO_PRINT =  max_readable_bytes4(holder,BYTES_TO_PRINT);

  if(BYTES_TO_PRINT > 0){
    jweezy << "JACK INDIRECT REFERENCE TABLE LOG ADDING OBJECT:\t";
    jweezy << android::base::StringPrintf("OBJECT ADDR: %p\t",holder);
    
    for(int j =0; j < BYTES_TO_PRINT; j++){
      jweezy << android::base::StringPrintf(" %x", ((unsigned char*)holder)[j] );//Log bytes at address
      continue;      

    }

    LOG(INFO) << jweezy.str();
  }
  #endif
  
  
  return obj;
}

inline void IndirectReferenceTable::Update(IndirectRef iref, ObjPtr<mirror::Object> obj) {
  DCHECK_EQ(GetIndirectRefKind(iref), kind_);
  uint32_t idx = ExtractIndex(iref);
  DCHECK_LT(idx, segment_state_.top_index);
  DCHECK_EQ(DecodeSerial(reinterpret_cast<uintptr_t>(iref)), table_[idx].GetSerial());
  DCHECK(!table_[idx].GetReference()->IsNull());
  table_[idx].SetReference(obj);
}

inline void IrtEntry::Add(ObjPtr<mirror::Object> obj) {
  ++serial_;
  if (serial_ == kIRTPrevCount) {
    serial_ = 0;
  }
  references_[serial_] = GcRoot<mirror::Object>(obj);
}

inline void IrtEntry::SetReference(ObjPtr<mirror::Object> obj) {
  DCHECK_LT(serial_, kIRTPrevCount);
  references_[serial_] = GcRoot<mirror::Object>(obj);
}

}  // namespace art

#endif  // ART_RUNTIME_INDIRECT_REFERENCE_TABLE_INL_H_
