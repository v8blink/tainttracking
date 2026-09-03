#include "third_party/blink/renderer/platform/wtf/text/taint_url_escape.h"

#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

const char kUpperHexDigits[] = "0123456789ABCDEF";

bool DontNeedEscape(UChar c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
         c == '~';
}

int HexValue(UChar c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

bool IsAsciiHexDigit(UChar c) {
  return HexValue(c) >= 0;
}

String Finalize(StringBuilder& builder, StringTaint& taint) {
  String output = builder.ToString();
  if (taint.hasTaint() && output.Impl()) {
    output.Impl()->SetTaint(taint);
  }
  return output;
}

}  // namespace

String TaintEscapeURL(const String& input, const StringTaint& taint) {
  StringBuilder result;
  StringTaint result_taint;
  unsigned length = input.length();
  for (unsigned i = 0; i < length; ++i) {
    UChar c = input[i];
    if (DontNeedEscape(c)) {
      result_taint.concat(taint.safeSubTaint(i, i + 1), result.length());
      result.Append(c);
    } else {
      unsigned start = result.length();
      result.Append('%');
      result.Append(kUpperHexDigits[(c >> 4) & 0xF]);
      result.Append(kUpperHexDigits[c & 0xF]);
      if (const TaintFlow* flow = taint.at(i)) {
        result_taint.append(TaintRange(start, start + 3, *flow));
      }
    }
  }
  return Finalize(result, result_taint);
}

String TaintUnescapeURL(const String& input, const StringTaint& taint) {
  StringBuilder result;
  StringTaint result_taint;
  unsigned length = input.length();
  unsigned i = 0;
  while (i < length) {
    UChar c = input[i];
    if (c == '+') {
      result_taint.concat(taint.safeSubTaint(i, i + 1), result.length());
      result.Append(' ');
      ++i;
      continue;
    }
    if (c == '%' && i + 2 < length && IsAsciiHexDigit(input[i + 1]) &&
        IsAsciiHexDigit(input[i + 2])) {
      result_taint.concat(taint.safeSubTaint(i, i + 1), result.length());
      result.Append(
          static_cast<UChar>(HexValue(input[i + 1]) * 16 + HexValue(input[i + 2])));
      i += 3;
      continue;
    }
    result_taint.concat(taint.safeSubTaint(i, i + 1), result.length());
    result.Append(c);
    ++i;
  }
  return Finalize(result, result_taint);
}

}  // namespace blink
