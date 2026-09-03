#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_WTF_TEXT_TAINT_URL_ESCAPE_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_WTF_TEXT_TAINT_URL_ESCAPE_H_

#include "taint/Taint.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_export.h"

namespace blink {

WTF_EXPORT String TaintEscapeURL(const String& input,
                                 const StringTaint& taint = EmptyTaint);

WTF_EXPORT String TaintUnescapeURL(const String& input,
                                   const StringTaint& taint = EmptyTaint);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_PLATFORM_WTF_TEXT_TAINT_URL_ESCAPE_H_
