#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_CONFIG_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_CONFIG_H_

#include <cstddef>

#include "third_party/blink/renderer/core/core_export.h"

namespace blink {

CORE_EXPORT bool TaintIsActive(const char* name);
CORE_EXPORT bool TaintIsSourceActive(const char* name);
CORE_EXPORT bool TaintIsSinkActive(const char* name);
CORE_EXPORT void TaintSetActive(const char* name, bool enabled);
CORE_EXPORT size_t TaintPrefCount();

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_CONFIG_H_
