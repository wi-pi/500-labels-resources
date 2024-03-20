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

#ifndef ART_RUNTIME_JNI_JNI_ENV_EXT_INL_H_
#define ART_RUNTIME_JNI_JNI_ENV_EXT_INL_H_

#include "jni_env_ext.h"
#include <fstream>
#include <sstream>
#include "android-base/stringprintf.h"
#include "mirror/object.h"

namespace art {

inline int max_readable_bytes5(void *ptr,int max) {
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


template<typename T>
inline T JNIEnvExt::AddLocalReference(ObjPtr<mirror::Object> obj) {
  std::string error_msg;
  IndirectRef ref = locals_.Add(local_ref_cookie_, obj, &error_msg);
  if (UNLIKELY(ref == nullptr)) {
    // This is really unexpected if we allow resizing local IRTs...
    LOG(FATAL) << error_msg;
    UNREACHABLE();
  }

  #ifdef __deez__
  int BYTES_TO_PRINT = 500;
  

  std::ostringstream jweezy;
  void* holder = (void*)obj.Ptr();

  BYTES_TO_PRINT =  max_readable_bytes5(holder,BYTES_TO_PRINT);

  if(BYTES_TO_PRINT > 0){
    jweezy << "JNI LOCAL REFERENCE:\t";
    jweezy << android::base::StringPrintf("OBJECT ADDR: %p\t",holder);
    
    for(int j =0; j < BYTES_TO_PRINT; j++){
      jweezy << android::base::StringPrintf(" %x", ((unsigned char*)holder)[j] );//Log bytes at address
      continue;      

    }

    LOG(INFO) << jweezy.str();
  }
  #endif
 

  // TODO: fix this to understand PushLocalFrame, so we can turn it on.
  if (false) {
    if (check_jni_) {
      size_t entry_count = locals_.Capacity();
      if (entry_count > 16) {
        locals_.Dump(LOG_STREAM(WARNING) << "Warning: more than 16 JNI local references: "
                                        << entry_count << " (most recent was a "
                                        << mirror::Object::PrettyTypeOf(obj) << ")\n");
      // TODO: LOG(FATAL) in a later release?
      }
    }
  }

  return reinterpret_cast<T>(ref);
}

}  // namespace art

#endif  // ART_RUNTIME_JNI_JNI_ENV_EXT_INL_H_
