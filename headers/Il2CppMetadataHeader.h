#include <stdint.h>

#ifndef IL2CPPMETADATAHEADER_H
  #define IL2CPPMETADATAHEADER_H
#endif

typedef struct __attribute__((packed)) Il2CppMetadataHeader {
    uint32_t magic;
    uint32_t version;

    struct {
        int32_t offset;
        int32_t length;
    } offset_length_pair[29];

} Il2CppMetadataHeader;

