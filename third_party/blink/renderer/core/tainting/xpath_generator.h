#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_XPATH_GENERATOR_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_XPATH_GENERATOR_H_

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"

namespace blink {

class Node;

CORE_EXPORT String GenerateXPath(const Node* node);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_XPATH_GENERATOR_H_
