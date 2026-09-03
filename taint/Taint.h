#ifndef _Taint_h
#define _Taint_h

#include <initializer_list>
#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <string_view>

#include "json.hpp"

#include <cassert>
#include <cstdlib>

#ifndef MOZ_ASSERT
#  define MOZ_ASSERT(cond, ...) assert(cond)
#endif
#ifndef MOZ_ASSERT_IF
#  define MOZ_ASSERT_IF(cond, expr) assert(!(cond) || (expr))
#endif
#ifndef MOZ_CRASH
#  define MOZ_CRASH(...) abort()
#endif
#ifndef MOZ_COUNT_CTOR
#  define MOZ_COUNT_CTOR(X)
#endif
#ifndef MOZ_COUNT_DTOR
#  define MOZ_COUNT_DTOR(X)
#endif

using json = nlohmann::json;

using TaintMd5 = std::array<unsigned char, 16>;

class TaintLocation {
 public:
  TaintLocation(std::u16string filename, uint32_t line, uint32_t pos,
                uint32_t next_line, uint32_t next_pos, uint32_t scriptStartLine,
                TaintMd5 scriptHash, std::u16string function);

  TaintLocation();

  TaintLocation(const TaintLocation& other) = default;
  TaintLocation& operator=(const TaintLocation& other) = default;

  TaintLocation(TaintLocation&& other) noexcept;
  TaintLocation& operator=(TaintLocation&& other) noexcept;

  const std::u16string& filename() const { return filename_; }
  uint32_t line() const { return line_; }
  uint32_t pos() const { return pos_; }
  uint32_t next_line() const { return next_line_; }
  uint32_t next_pos() const { return next_pos_; }
  uint32_t scriptStartLine() const { return scriptStartLine_; }
  const TaintMd5& scriptHash() const { return scriptHash_; }
  const std::u16string& function() const { return function_; }

 private:
  std::u16string filename_;
  uint32_t line_;
  uint32_t pos_;
  uint32_t next_line_;
  uint32_t next_pos_;
  uint32_t scriptStartLine_;
  TaintMd5 scriptHash_;
  std::u16string function_;
};

class TaintOperation {
 public:
  TaintOperation(const char* name, std::initializer_list<std::u16string> args);

  TaintOperation(const char* name, std::vector<std::u16string> args);

  TaintOperation(const char* name, TaintLocation location,
                 std::initializer_list<std::u16string> args);

  TaintOperation(const char* name, TaintLocation location,
                 std::vector<std::u16string> args);

  explicit TaintOperation(const char* name);

  TaintOperation(const char* name, TaintLocation location);

  TaintOperation(const TaintOperation& other) = default;
  TaintOperation& operator=(const TaintOperation& other) = default;

  TaintOperation(TaintOperation&& other) noexcept;
  TaintOperation& operator=(TaintOperation&& other) noexcept;

  const char* name() const { return name_.c_str(); }
  const std::vector<std::u16string>& arguments() const { return arguments_; }
  const TaintLocation& location() const { return location_; }

  bool isSource() const { return source_; }
  void setSource() { source_ = true; }

 private:

  std::string name_;

  std::vector<std::u16string> arguments_;

  bool source_;

  TaintLocation location_;
};

class TaintNode {
 public:

  TaintNode(TaintNode* parent, const TaintOperation& operation);

  explicit TaintNode(const TaintOperation& operation);

  TaintNode(TaintNode* parent, TaintOperation&& operation) noexcept;

  explicit TaintNode(TaintOperation&& operation) noexcept;

  void addref();

  void release();

  TaintNode* parent() { return parent_; }

  const TaintOperation& operation() const { return operation_; }

 private:

  ~TaintNode();

  TaintNode* parent_;

  std::atomic_uint32_t refcount_;

  TaintOperation operation_;

  TaintNode(const TaintNode& other) = delete;
  TaintNode& operator=(const TaintNode& other) = delete;
};

class TaintFlow {
 private:

  class Iterator {
   public:
    explicit Iterator(TaintNode* head);
    Iterator();

    Iterator(const Iterator& other);

    Iterator& operator++();
    TaintNode& operator*() const;
    bool operator==(const Iterator& other) const;
    bool operator!=(const Iterator& other) const;

   private:
    TaintNode* current_;
  };

 public:

  TaintFlow();

  explicit TaintFlow(TaintNode* head);

  explicit TaintFlow(const TaintOperation& source);

  TaintFlow(const TaintFlow& other);

  TaintFlow(TaintFlow&& other) noexcept;

  explicit TaintFlow(const TaintFlow* other);

  ~TaintFlow();

  TaintFlow& operator=(const TaintFlow& other);

  TaintNode* head() const { return head_; }

  const TaintOperation& source() const;

  TaintFlow& extend(const TaintOperation& operation);

  TaintFlow& extend(const TaintOperation& operation) const;

  TaintFlow& extend(TaintOperation&& operation);

  TaintFlow::Iterator begin() const;
  TaintFlow::Iterator end() const;

  static TaintFlow extend(const TaintFlow& flow,
                          const TaintOperation& operation);

  static TaintFlow append(const TaintFlow& first, const TaintFlow& second);

  bool operator==(const TaintFlow& other) const { return head_ == other.head_; }
  bool operator!=(const TaintFlow& other) const { return head_ != other.head_; }

  bool isNotEmpty() const { return !!head_; }

  explicit operator bool() const { return isNotEmpty(); }

  static const TaintFlow& getEmptyTaintFlow();

 private:

  TaintNode* head_;

  static TaintFlow empty_flow_;
};

class TaintRange {
 public:

  TaintRange();

  TaintRange(uint32_t begin, uint32_t end, TaintFlow flow);

  TaintRange(const TaintRange& other);

  ~TaintRange();

  TaintRange& operator=(const TaintRange& other);

  bool operator<(const TaintRange& other) const;
  bool operator<(uint32_t index) const;
  bool operator>(uint32_t index) const;
  bool operator==(uint32_t index) const;

  bool contains(uint32_t index) const;

  TaintFlow& flow() { return flow_; }
  const TaintFlow& flow() const { return flow_; }

  uint32_t begin() const { return begin_; }

  uint32_t end() const { return end_; }

  void resize(uint32_t begin, uint32_t end);

  void toBase64();

  void fromBase64();

 private:
  static uint32_t convertBaseBegin(uint32_t ntet, uint32_t nwidth,
                                   uint32_t m_tet);
  static uint32_t convertBaseEnd(uint32_t ntet, uint32_t nwidth,
                                 uint32_t m_tet);

  uint32_t begin_, end_;

  TaintFlow flow_;
};

class SafeStringTaint;

class StringTaint {
 public:

  explicit constexpr StringTaint() : ranges_(nullptr) {}

  explicit StringTaint(const TaintRange& range);

  StringTaint(uint32_t begin, uint32_t end, const TaintOperation& operation);

  explicit StringTaint(const TaintFlow& flow, uint32_t length);

  ~StringTaint() = default;

  StringTaint(const StringTaint& other);
  StringTaint(StringTaint&& other) noexcept;
  StringTaint& operator=(const StringTaint& other);
  StringTaint& operator=(StringTaint&& other) noexcept;

  StringTaint(const StringTaint& other, uint32_t begin, uint32_t end);
  StringTaint(const StringTaint& other, uint32_t index);

  bool hasTaint() const { return !!ranges_; }

  explicit operator bool() const { return hasTaint(); }

  void clear();

  void clearBetween(uint32_t begin, uint32_t end);

  void clearAfter(uint32_t index) { clearBetween(index, -1); }

  void clearAt(uint32_t index) { clearBetween(index, index + 1); }

  void shift(uint32_t index, int amount);

  void insert(uint32_t index, const StringTaint& taint);

  void replace(uint32_t begin, uint32_t end, const StringTaint& taint) {
    clearBetween(begin, end);
    insert(begin, taint);
  }

  void replace(uint32_t begin, uint32_t end, uint32_t length,
               const StringTaint& taint) {
    clearBetween(begin, end);
    shift(begin, length - (end - begin));
    insert(begin, taint);
  }

  const TaintFlow* at(uint32_t index) const;
  const TaintFlow* operator[](uint32_t index) const { return at(index); }
  const TaintFlow& atRef(uint32_t index) const;

  void set(uint32_t index, const TaintFlow& flow);

  StringTaint& subtaint(uint32_t begin, uint32_t end);

  StringTaint& subtaint(uint32_t index);

  StringTaint& extend(const TaintOperation& operation);

  StringTaint& extend(TaintOperation&& operation);

  StringTaint& overlay(uint32_t begin, uint32_t end,
                       const TaintOperation& operation);

  StringTaint& overlay(uint32_t begin, uint32_t end, const TaintFlow& flow);

  StringTaint& append(TaintRange range);

  void concat(const StringTaint& other, uint32_t offset);

  void concat(const TaintFlow& other, uint32_t offset);

  StringTaint& toBase64();

  StringTaint& fromBase64();

  std::vector<TaintRange>::iterator begin();
  std::vector<TaintRange>::iterator end();
  std::vector<TaintRange>::const_iterator begin() const;
  std::vector<TaintRange>::const_iterator end() const;

  SafeStringTaint safeCopy() const;
  SafeStringTaint safeSubTaint(uint32_t begin, uint32_t end) const;
  SafeStringTaint safeSubTaint(uint32_t index) const;

 private:

  void assign(std::vector<TaintRange>* ranges);

  void removeOverlaps();

  void assignFromSubTaint(const StringTaint& other, uint32_t begin,
                          uint32_t end);

  std::vector<TaintRange>* ranges_;
};

static_assert(sizeof(StringTaint) == sizeof(void*),
              "Class StringTaint must be compatible with a raw pointer.");

#define EmptyTaint (StringTaint())

class SafeStringTaint : public StringTaint {
 public:

  explicit constexpr SafeStringTaint() : StringTaint() {}

  explicit SafeStringTaint(TaintRange range) : StringTaint(range) {}

  SafeStringTaint(uint32_t begin, uint32_t end, const TaintOperation& operation)
      : StringTaint(begin, end, operation) {}

  explicit SafeStringTaint(TaintFlow flow, uint32_t length)
      : StringTaint(flow, length) {}

  ~SafeStringTaint() { clear(); }

  SafeStringTaint(const SafeStringTaint& other) : StringTaint(other) {}
  SafeStringTaint(SafeStringTaint&& other) noexcept
      : StringTaint(std::move(other)) {}
  SafeStringTaint& operator=(const SafeStringTaint& other) {
    StringTaint::operator=(other);
    return *this;
  }
  SafeStringTaint& operator=(SafeStringTaint&& other) noexcept {
    StringTaint::operator=(other);
    return *this;
  }

  SafeStringTaint(const StringTaint& other, uint32_t begin, uint32_t end)
      : StringTaint(other, begin, end) {}
  SafeStringTaint(const StringTaint& other, uint32_t index)
      : StringTaint(other, index) {}

  explicit SafeStringTaint(const StringTaint& other) : StringTaint(other) {}
  explicit SafeStringTaint(StringTaint&& other) noexcept : StringTaint(other) {}
  SafeStringTaint& operator=(const StringTaint& other) {
    StringTaint::operator=(other);
    return *this;
  }
  SafeStringTaint& operator=(StringTaint&& other) noexcept {
    StringTaint::operator=(other);
    return *this;
  }
};

class TaintableString {
 public:
  TaintableString() : taint_() {}

  ~TaintableString() { taint_.clear(); }

  bool isTainted() const { return taint_.hasTaint(); }
  bool IsTainted() const { return taint_.hasTaint(); }

  const StringTaint& taint() const { return taint_; }
  const StringTaint& Taint() const { return taint_; }
  StringTaint& taint() { return taint_; }
  StringTaint& Taint() { return taint_; }

  void setTaint(const StringTaint& new_taint) { taint_ = new_taint; }
  void AssignTaint(const StringTaint& new_taint) { taint_ = new_taint; }
  void setTaint(StringTaint&& new_taint) { taint_ = new_taint; }
  void AssignTaint(StringTaint&& new_taint) { taint_ = new_taint; }

  void clearTaint() { taint_.clear(); }
  void ClearTaint() { taint_.clear(); }

  void clearTaintAfter(uint32_t index) { taint_.clearAfter(index); }
  void ClearTaintAfter(uint32_t index) { taint_.clearAfter(index); }

  void clearTaintAt(uint32_t index) { taint_.clearAt(index); }
  void ClearTaintAt(uint32_t index) { taint_.clearAt(index); }

  void ReplaceTaint(uint32_t begin, uint32_t end, uint32_t length,
                    const StringTaint& taint) {
    taint_.replace(begin, end, length, taint);
  }

  void appendTaintAt(uint32_t offset, const StringTaint& taint) {
    taint_.concat(taint, offset);
  }
  void AppendTaintAt(uint32_t offset, const StringTaint& taint) {
    taint_.concat(taint, offset);
  }

  void insertTaintAt(uint32_t offset, const StringTaint& taint) {
    taint_.insert(offset, taint);
  }
  void InsertTaintAt(uint32_t offset, const StringTaint& taint) {
    taint_.insert(offset, taint);
  }

  void initTaint() { new (&taint_) SafeStringTaint(); }
  void InitTaint() { initTaint(); }

  void finalize() { taint_.clear(); }

 protected:

  SafeStringTaint taint_;
};

static_assert(sizeof(TaintableString) == sizeof(StringTaint),
              "Class TaintableString must be binary compatible with a "
              "StringTaint instance.");

class TaintList {
 public:

  explicit constexpr TaintList() : flows_(nullptr) {}

  ~TaintList() { clear(); }

  bool hasTaint() const { return !!flows_; }

  void clear();

  TaintList& append(TaintFlow range);

  std::vector<TaintFlow>::iterator begin();
  std::vector<TaintFlow>::iterator end();
  std::vector<TaintFlow>::const_iterator begin() const;
  std::vector<TaintFlow>::const_iterator end() const;

 private:

  std::vector<TaintFlow>* flows_;
};

StringTaint ParseStringTaintForE2E(const std::string& input);

std::string SerializeStringTaintForE2E(const StringTaint& taint,
                                       bool addSinks = false);

StringTaint ParseStringTaint(std::string aInput);

std::string SerializeStringTaint(const StringTaint& aTaint);

StringTaint LoadStringTaintFromJSON(const json& aData);

json DumpStringTaintAsJSON(const StringTaint& aTaint);

TaintRange LoadTaintRangeFromJSON(const json& aData);

json DumpTaintRangeAsJSON(const TaintRange& aRange);

TaintFlow LoadTaintFlowFromJSON(const json& aData);

json DumpTaintFlowAsJSON(const TaintFlow& aFlow);

TaintOperation LoadTaintOperationFromJSON(const json& aData);

json DumpTaintOperationAsJSON(const TaintOperation& aOperation);

TaintLocation LoadTaintLocationFromJSON(const json& aData);

json DumpTaintLocationAsJSON(const TaintLocation& aLocation);

#endif
