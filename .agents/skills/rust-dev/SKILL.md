---
name: rust-dev
description: Type system, safety, optimization and workflows. Use this skill on all rust projects.
---

# 安全与类型

## 类型安全

- 解析，而非验证。将约束编码到类型中，不在业务路径中重复验证。
  - 业务代码 & 库：调用者不得使用 `panic!`/`expect`/`unwrap`/`unsafe`。`unsafe` 仅允许在维护不变量的类型/模块内部使用，并需加上 `debug_assert!` 和安全注释。
  - 测试 & 入口点：允许使用 `expect`/`unwrap`。

- 将错误处理推至边界层，如IO、FFI层。业务层专注有业务意义的失败模式。
  - 避免在业务路径中出现防御性分支和无意义的兜底；使用类型系统消除不可能状态。
  - 删除死代码、关键路径上的no-op。分支必须有真实语义。
  - 库内部错误优先 panic。由于 rust 类型系统限制，这是可接受的。

- 最小化可见性。如果不变量依赖于私有字段或私有方法，则只暴露最小必要范围的访问。经验法则：如果一个类型是其字段笛卡尔积的*真子集*，则这些字段应保持私有。示例：
  - `User` 要求至少提供 `email` 或 `phone`，因此字段应私有，并在 setter/ctor 中验证。
  - 如果不变量仅涉及单个字段，将该字段包装为 newtype，而非私有化整个结构体。例如：使用 `Email(Box<str>)` 而非 `User { email: Box<str>, ... }`。
  - 对于承载逻辑的类型（如 `Service`/`Manager`/`Controller` 等），字段几乎总是应为私有。
  - 例外：DTO 及其他 named tuple 类型可保持字段公开。

## Unsafe 审计单元

每个 unsafe 抽象都需要一个审计单元。优先选择 crate 作为审计单元。在 unsafe 审计单元内部修改安全函数，重新检查所有的 unsafe 块。unsafe 块需要面向依赖关系的 `// SAFETY:` 注释：

```rust
// SAFETY:
// Required by `ptr.add(i).read()`:
// - `ptr` points to one allocation containing at least `len` initialized elements.
// - `i < len`.
// Maintained by:
// - `Inner::new` initializes `ptr`, `len`, and `cap` consistently.
// - `Inner::push` increments `len` only after writing the element.
// Trusted callees:
// - no user-provided trait methods or callbacks are used to justify memory safety.
unsafe { ptr.add(i).read() }
```

不能写 `// SAFETY: invariant holds for this type.`。对依赖项需要分类：

| 种类 | 规则 |
| - | - |
| 审计单元内的函数、类型和 sealed trait | 可信任。修改需要重新审计。 |
| 下游实现：trait、回调 | 不可信。 |
| `unsafe fn`、`unsafe trait` | 可信任。 |

对于形如 `fn foo<T>(arg: T)` 的函数，优先使用 `unsafe trait`。不要标记为 `unsafe fn` 并写无意义的 `// SAFETY: invariant holds for caller supplied arg.`。

## Rustdoc

完善 Rustdoc，包括 private items。

为类型写的文档需要有
- 当前紧凑类型在语义上对应的朴素ADT是什么，即数学定义。
- 解释编码规则。包括语义值和不变量两方面。语义值为对上述朴素类型的映射，不变量为不可能出现的编码。

示例
```rust
/// Email address.
///
/// Semantically, an email address is `LocalPart × DomainPart`.
///
/// where:
/// - `LocalPart` is ...,
/// - `DomainPart` is ....
///
/// # Encoding
///
/// - `(LocalPart, DomainPart)` → `format!("{local}@{domain})`, offset = `local.len()`.
/// - Invariants: The string contains exactly one `@`, ...
///
/// Because the constructor enforces the invariants, `local_part()` and `domain_part()` can slice
/// directly using the known offset without re‑validation.
///
/// # Example
///
/// ```
/// ...
/// ```
struct Email {full: Box<str>,at_offset: u32}
```

# 复杂度与优化

## 复杂度契约

实现数据结构或算法前编写复杂度表格。

| Operation | Frequency | Complexity | Data structure | Forbidden Impl |
| - | - | - | - | - |
| ... | ... | ... | ... | ... |

## 存储策略

| Need | Representation |
| - | - |
| no storage | recompute or borrow |
| append-only immutable payload | `bumpalo`, `Vec<T>`, arena |
| append-only typed objects | `Vec<T>` plus ID |
| deletion or compaction | custom arena with tracing or freelist |
| cross-thread immutable sharing | `Arc<T>`, `Arc<[T]>`, `Arc<str>` |

- 不需要存的不存，重复信息只存一份。
  - 可以从其他字段在 O(1) 时间内重新计算出的数据，都不存。例如：可推导的长度、校验和、预计算哈希（除非热点剖面证明其必要）。
  - 可以从其他存储取得的数据，优先借用，也不自己存。
- 对于不可变变长数据
  - 首先选用 `bumpalo` 或 nightly 分配器。
  - 其次选用 `Box<[T]>` 和 `Box<str>`。但生命周期短时，会造成高昂的递归 Drop 和分配成本。
  - 禁止使用 `Vec<T>` 和 `String`。
- 对于可变变长数据
  - 使用 `Vec<T>` 和 `String`，或者 tracing arena。
- 对于定长数据
  - 使用 `Vec<T>` + ID，需要删除时使用 freelist。
- 对于引用计数
  - 禁止使用 `Rc`。在单线程上下文中，必须通过清晰的单一所有权或借用解决共享，无法解决时重新审视架构。
  - `Arc` 仅允许用于跨线程共享不可变数据，不得用于可变共享或单线程场景。
  - 需要共享可变状态时，优先考虑基于索引的句柄配合 arena 分配，或使用通道传递所有权。
- 保留复杂度契约需要的索引结构，避免为方便而构建辅助映射。

### 整数和打包

- 使用 `u32` ID。多数情况，`u32` ID 随对象死亡而复用，因此足够安全。
- 若值域允许，优先使用 `u8/i8`、`u16/i16`。
- 当一个大的标量可拆分为多个不同含义且各自有界的小字段时，应手动分包。
- 算术运算和潜在无界的数值：使用 `i64/u64`。

### Enum, Option 和填充

- 倾向 SoA。实现细节：避免 `Vec<field1>, Vec<field2>…` 逐字段分配。由于这些 Vec 总是同步增长，应合并为单个 `Vec<u8>` 或 `Vec<u64>`，按 stride 编排字段为 SoA，并封装安全的访问器。
- niche 优化：利用 Rust 枚举和 `Option` 已有的 niche 拟合，或手动实现 niche。
- 位向量可能是负优化。顺序访问、带宽瓶颈时可做 `bitvec` 优化，否则不优化。

## 减少分配

- 循环内复用：临时缓冲区通过 `.clear()` 重置以保留容量。
- 跨生命周期复用：评估将分配从局部作用域提升到外层结构或调用者。
  - 禁止返回不必要的堆分配容器，例如 `Vec<T>`、`String`、`Box<dyn Error>`。
  - 优先接受 `&mut [T]`、`&mut impl Write` 等参数，返回 `impl Iterator<Item = T>` 或提供 `visit`。

## 激进 `#[inline(always)]`

- 跨函数分析能获得性能收益的函数都应标注。即存在某个前置条件，满足后函数内的panic检查变成死代码。
- llvm内联经过多层转发的函数容易失败，这类函数需适当标注。

## 4. 减少 Indirection

- 当内联（嵌入）字段既能消除一次指针跳转，又不会显著增大所在结构体体积时，务必内联。
- 若两者冲突，应追求帕累托最优：没有多余的跳转，且没有无谓的体积膨胀。通过性能剖面指导最终决策。
- 当现有抽象无法满足紧凑和零间接的要求时，可能需要手动实现自定义 DST fat pointer。
  - 不建议手写 thin pointer + pointee header 存储长度。
- 对于树或嵌套结构，如果访问模式极其规律，如先序遍历，应优先使用无指针的序列表示：
  - balanced parentheses 序列
  - 基于 S-Expression 的扁平化序列

# 开发工作流

保持代码无 clippy 警告。不管是不是这次改动引入的，只要有就清理掉。

### 1. 初始化仓库并实现 v1

- 一开始就要考虑：系统边界、端到端正向路径、错误模型。
- 尽早拆分 crate。最小示例：每个 crate 包含一个 `lib.rs`，几十到小几百行代码。更长代码需要进一步拆分为模块。
- 设计类型，用伪代码起草定义。要求：
  - 对（几乎）所有内容使用 newtype。例如：`UserId(u32)`、`Email(Box<str>)`。
  - 谨慎应用编码风格中的可见性规则。
  - 为热点类型设计高效内存布局。
- 交付物：需求文档（包含用例和测试用例）、项目骨架、类型系统。

### 2. 实现一个特性

- 研究基线，理解当前行为，可运行代码、添加临时日志。
- 重新表述需求以避免返工。尽可能将其表达为精确的行为差异。
- 不破坏组织与分层。将新代码放到正确位置，或创建新模块。

### 3. 重构现有代码

#### 原则

- 重构的目标是让代码更易于推理。
- 避免只拆分大函数为小函数，却不减少每个单元必须依赖的前置条件。会达成使控制流更加分散的反效果，务必不要这么做。
- 如果为简化推理而有意改变行为，则视为需求变更，并明确描述行为差异。
- 优先选择能处理复杂度的重构：
  - 当约定足够时，不引入配置。
  - 让行为更数据驱动、声明式，例如使用表、枚举、宏。
  - 宏参数可能被惰性、有条件或多次求值（大多数情况都是这样），此时建议使用闭包语法 `|| ...` 而非普通表达式 `expr`。
- 优先选择暴露有效状态转换的类型，而不是过宽的可变表面和不受约束的 setter。

#### 步骤

- 研究基线，理解当前行为。
- 重新表述并确认现有业务语义是否仍然必要。如果需求已过时，可以改变行为。
- 确保重构彻底：删除死代码，检查是否存在绕过重构后的代码的路径。禁止留 wrapper 或 re-export。
- 死代码标准：clippy警告的死代码，外加死 `pub` 函数。除非项目另有说明，否则假设 workspace 的内部 crate 不承诺 API 稳定，死 `pub` 函数可以放心删除。
- 对于大型重构，创建一个实验性 crate。
