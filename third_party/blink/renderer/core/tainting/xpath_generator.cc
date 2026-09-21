#include "third_party/blink/renderer/core/tainting/xpath_generator.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

bool IsNonWordCharacter(UChar c) {
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') || c == '_') {
    return false;
  }
  return true;
}

bool ContainsNonWordCharacter(const String& str) {
  for (unsigned i = 0; i < str.length(); ++i) {
    if (IsNonWordCharacter(str[i])) {
      return true;
    }
  }
  return false;
}

String GetPrefix(const Node* node) {
  if (node->IsHTMLElement()) {
    return "xhtml";
  }
  return String();
}

String GetNameAttribute(const Node* node) {
  const auto* element = DynamicTo<Element>(node);
  if (!element) {
    return String();
  }
  return element->GetNameNoTainting().GetString();
}

String GenerateConcatExpression(const String& str) {
  StringBuilder inner;
  unsigned len = str.length();
  bool in_non_quote = false;
  unsigned non_quote_begin = 0;
  bool in_quote = false;
  unsigned quote_begin = 0;
  unsigned cur = 0;
  for (; cur < len; ++cur) {
    if (str[cur] == '\'') {
      if (in_non_quote) {
        inner.Append(str, non_quote_begin, cur - non_quote_begin);
        in_non_quote = false;
      }
      if (!in_quote) {
        inner.Append("',\"");
        in_quote = true;
        quote_begin = cur;
      }
    } else {
      if (!in_non_quote) {
        in_non_quote = true;
        non_quote_begin = cur;
      }
      if (in_quote) {
        inner.Append(str, quote_begin, cur - quote_begin);
        inner.Append("\",'");
        in_quote = false;
      }
    }
  }
  if (in_quote) {
    inner.Append(str, quote_begin, cur - quote_begin);
    inner.Append("\",'");
  } else if (in_non_quote) {
    inner.Append(str, non_quote_begin, cur - non_quote_begin);
  }

  StringBuilder result;
  result.Append("concat('");
  result.Append(inner.ToString());
  result.Append("')");
  return result.ToString();
}

String QuoteArgument(const String& arg) {
  if (arg.find('\'') == kNotFound) {
    StringBuilder result;
    result.Append('\'');
    result.Append(arg);
    result.Append('\'');
    return result.ToString();
  }
  if (arg.find('"') == kNotFound) {
    StringBuilder result;
    result.Append('"');
    result.Append(arg);
    result.Append('"');
    return result.ToString();
  }
  return GenerateConcatExpression(arg);
}

String EscapeName(const String& name) {
  if (ContainsNonWordCharacter(name)) {
    StringBuilder result;
    result.Append("*[local-name()=");
    result.Append(QuoteArgument(name));
    result.Append(']');
    return result.ToString();
  }
  return name;
}

}  // namespace

String GenerateXPath(const Node* node) {
  if (!node || !node->parentNode()) {
    return String();
  }

  const auto* element = DynamicTo<Element>(node);
  String node_namespace = element ? String(element->namespaceURI()) : String();
  String node_local_name =
      element ? String(element->localName()) : node->nodeName();

  String prefix = GetPrefix(node);
  String escaped_name = EscapeName(node_local_name);
  StringBuilder tag;
  if (prefix.empty()) {
    tag.Append(escaped_name);
  } else {
    tag.Append(prefix);
    tag.Append(':');
    tag.Append(escaped_name);
  }

  if (element && element->HasID()) {
    String elem_id = element->GetIdNoTainting().GetString();
    StringBuilder result;
    result.Append("//");
    result.Append(tag.ToString());
    result.Append("[@id=");
    result.Append(QuoteArgument(elem_id));
    result.Append(']');
    return result.ToString();
  }

  int count = 1;
  String node_name_attribute = GetNameAttribute(node);
  for (Element* sibling =
           element ? const_cast<Element*>(element)->previousElementSibling()
                   : nullptr;
       sibling; sibling = sibling->previousElementSibling()) {
    String sibling_namespace = sibling->namespaceURI();
    String sibling_name_attribute = GetNameAttribute(sibling);
    if (String(sibling->localName()) == node_local_name &&
        sibling_namespace == node_namespace &&
        (node_name_attribute.empty() ||
         sibling_name_attribute == node_name_attribute)) {
      ++count;
    }
  }

  StringBuilder name_part;
  if (!node_name_attribute.empty()) {
    name_part.Append("[@name=");
    name_part.Append(QuoteArgument(node_name_attribute));
    name_part.Append(']');
  }
  StringBuilder count_part;
  if (count != 1) {
    count_part.Append('[');
    count_part.AppendNumber(count);
    count_part.Append(']');
  }

  StringBuilder result;
  result.Append(GenerateXPath(node->parentNode()));
  result.Append('/');
  result.Append(tag.ToString());
  result.Append(name_part.ToString());
  result.Append(count_part.ToString());
  return result.ToString();
}

}  // namespace blink
