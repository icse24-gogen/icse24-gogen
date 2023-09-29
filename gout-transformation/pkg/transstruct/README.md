# ReadMe

## What to do

## How to use

*20210902更新：统一使用`GetFuzzData`api在Fuzz入口中将data []byte转化为fuzz函数需要的数据类型*

### 导入

在fuzz函数所在go文件中使用`import "xxx.com/jxzhang/transstruct"`导入本package
在go.mod文件中使用replace将`xxx.com/jxzhang/transstruct`替换为本目录地址

### api调用

#### 生成初始corpus
使用`transstruct.GenerateInitCorpus(initobj interface{})`生成初始corpus，参数`initobj`为原Test函数中的初始输入变量.
例：`transstruct.GenerateInitCorpus(AnyVar)`


#### 获取Fuzz函数输入
现在统一使用`transstruct.GetFuzzData(initobj interface{}, data []byte)`作为获取Fuzz函数输入变量的API，其中`initobj`变量为原Test函数中的输入变量，`data`为从后端获取的用于Fuzz的byte流，即Fuzz入口函数的参数。

具体用法如下：
1. string类型输入的Fuzz入口
 ```go
 func FuzzXxx(data []byte) int{
     // ...
     initInput := "init str input"
     fuzzData := transstruct.GetFuzzData(initInput, data).(string)
     foo(fuzzData)
     // ...
     return 0
 }
 ```
 调用GetFuzzData后需要对返回值进行string类型转换

2. []byte类型输入的Fuzz入口
 ```go
 func FuzzXxx(data []byte) int{
     // ...
     initInput := "init []byte input"
     fuzzData := transstruct.GetFuzzData(initInput, data).([]byte)
     foo(fuzzData)
     // ...
     return 0
 }
 ```
 调用GetFuzzData后需要对返回值进行[]byte类型转换

3. struct类型输入的Fuzz入口

 **具名结构体**

 ```go
 func FuzzXxx(data []byte) int{
     // ...
     initInput := StructName{
         // init assignment for members of the struct
         //
     }
     fuzzData := transstruct.GetFuzzData(initInput, data).(StructName)
     foo(fuzzData)
     // ...
     return 0
 }
 ```
 调用GetFuzzData后需要对返回值根据`InitInput`的结构体类型名称进行类型转换.

 **匿名结构体**
 ```go
 func FuzzXxx(data []byte) int{
     // ...
     initInput := struct{
         m1 int
         m2 []string
     }{
         m1: 0,
         m2: []string{"aaa", "bbb"},
     }
     fuzzData := transstruct.GetFuzzData(initInput, data).(struct {
         m1 int
         m2 []string
     })
     foo(fuzzData)
     // ...
     return 0
 }
 ```
 和具名结构体有相同的处理步骤，但对`GetFuzzData`进行类型转换时需要使用完整的结构体定义。
