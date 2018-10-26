###############################################################################
#
# A smart Makefile template for GNU/LINUX programming
#
# Date:   2012/10/24
#
# Usage:
#   $ make           Compile and link (or archive)
#   $ make clean     Clean the objectives and target.
###############################################################################

OPTIMIZE := #-O2
WARNINGS := #-Wall -Wno-unused -Wno-format -Wno-strict-aliasing
DEFS     :=
EXTRA_CFLAGS := -g -DDEBUG #-m32

#定义一些变量，编译链接时使用
INC_DIR   =             #include目录
SRC_DIR   = .   #源代码目录，表示编译时去当前SRC_DIR目录下查找源文件
OBJ_DIR   = out	#目标文件目录， 表示编译后生成的.o文件存放目录， 用以链接使用
EXTRA_SRC =     #一些额外增加或者文件比较分散的源文件
EXCLUDE_FILES =	#排除的文件列表

SUFFIX       = c 	#源文件后缀，表示源代码可以支持的源文件后缀
TARGET       := hilink_server	#生成目标名称
#TARGET_TYPE  := ar		#目标类型 表示是静态链接目标文件
#TARGET_TYPE  := so		#表示是动态链接目标文件
TARGET_TYPE  := app		#表示是生成应用程序

LDFLAGS += -lpthread

#####################################################################################
#  Do not change any part of them unless you have understood this script very well  #
#  This is a kind remind.                                                           #
#####################################################################################

#FUNC#  Add a new line to the input stream.
#定义一个变量
define add_newline
$1

endef

#Makefile 函数
#1.反过滤函数——filter-out。
#$(filter-out <pattern...>,<text> )

#2. foreach函数
#foreach 函数和别的函数非常的不一样。因为这个函数是用来做循环用的，Makefile 中的 
#foreach 函数几乎是仿照于 Unix 标准 Shell（/bin/sh）中的 for 语句，或是 C-Shell 
#（/bin/csh）中的foreach语句而构建的 语法：
#$(foreach <var>,<list>,<text> )
##$(foreach <var>,<list>,<test>) 把函数<list>中的单词逐一取出放到参数<var>所指定的变量中，然后再执行<text>所包含的表达式。每一次<text>会返回一个字符串，循环过程中，<text>的所#
#返回的每个字符串会以空格分割，最后当整个循环结束时，<text>所返回的每个字符串所组成的整个字符串将会是foreach函数的返回值
#举例：$(foreach d,$(sort $(INC_DIR) $(SRC_DIR)),-I$d)
# INC_DIR=../include 
# SRC_DIR=./src 

#3. wildcard函数
#语法： $(wildcard PATTERN)
#列出当前目录下所有符合模式“PATTERN”格式的文件名
#举例：$(wildcard *.c) 返回值为当前目录下所有.c源文件列表

#4. 模式字符串替换函数——patsubst
#功能：查找<text>中的单词（单词以“空格”、“Tab”或“回车”“换行”分隔）是否 
#符合模式<pattern>，如果匹配的话，则以<replacement>替换。这里，<pattern>可以包##括通配符“%”，表示任意长度的字串。如果<replacement>中也包含“%”，那么， 
##<replacement>中的这个“%”将是<pattern>中的那个“%”所代表的字串。（可以######用“\” 来转义，以“\%”来表示真实含义的“%”字符） 
#返回：函数返回被替换过后的字符串。
#$(patsubst %.c,%.o, x.c.c bar.c)
#把字串“x.c.cbar.c”符合模式[%.c]的单词替换成[%.o]，返回结果是“x.c.obar.o”

#5.使用：SRC = $(notdir wildcard)
#去除所有的目录信息，SRC里的文件名列表将只有文件名。

#6 eval函数详解http://bbs.chinaunix.net/thread-2321462-3-1.html
#FUNC# set the variable `src-x' according to the input $1
define set_src_x
src-$1 = $(filter-out $4,$(foreach d,$2,$(wildcard $d/*.$1)) $(filter %.$1,$3))
endef 
#这里定义一个变量，后面会用到(会在这里用到$(eval $(foreach i,$(SUFFIX),$(call set_src_x,$i,$(SRC_DIR),$(EXTRA_SRC),$(EXCLUDE_FILES)))) )
#src-$1的意思是 在call调用之后， 这里会变成：
#src-$i = $(filter-out $(EXCLUDE_FILES), $(foreach d, $(SRC_DIR), $(wildcard $d/*.$i)) $(filter #%.$1, $(EXTRA_SRC) )
#这里$i 是SUFFIX中的c cpp cxx $(prefix_objdir) = out, $(SRC_DIR)=src, 
#这句话意思是遍历src_dir 找到src_dir里所有的.c文件和EXTRA_SRC里的所有文件，通过排除掉#EXCLUDE_FILES文件夹里的文件。

#FUNC# set the variable `obj-x' according to the input $1
define set_obj_x	
obj-$1 = $(patsubst %.$1,$3%.o,$(notdir $2))
endef
#同样的后面也会用到,
#这里在call之后会变成 obj-c = $(patsubst %.c,$(prefix_objdir)%.o, $(notdir $(src-c)))
#这里意思就是obj-c = 把.c名字替换成.o名字，且这个.o有$(prefix_objdir)前缀 即out/*.o这种形式#（同时排除src-c里面的目录文件）

#VAR# Get the uniform representation of the object directory path name
ifneq ($(OBJ_DIR),)	#如果OBJ_DIR不为空，
prefix_objdir := $(filter-out /,$(prefix_objdir)/)	
endif
#prefix_objdir  = $(shell echo $(OBJ_DIR)|sed 's:\(\./*\)*::')	#prefix_objdir = (后面这个函数执行#后， 这里OBJ_DIR=out, 这里是把./过滤掉， out没有./ prefix_objdir = out)
##/反过滤函数， 过滤掉匹配的模式，这里是吧匹配/的过滤掉，即 /不能是out的输出

GCC      := $(CROSS_COMPILE)gcc
G++      := $(CROSS_COMPILE)gcc
SRC_DIR := $(sort . $(SRC_DIR))
inc_dir = $(foreach d,$(sort $(INC_DIR) $(SRC_DIR)),-I$d)
#include的目录， 执行完成makefile的函数后， inc_dir = -lsrc/

#--# Do smart deduction automatically
$(eval $(foreach i,$(SUFFIX),$(call set_src_x,$i,$(SRC_DIR),$(EXTRA_SRC),$(EXCLUDE_FILES)))) 
#这个makefile函数 call set_src_x 
$(eval $(foreach i,$(SUFFIX),$(call set_obj_x,$i,$(src-$i),$(prefix_objdir))))
#这个makefile函数 调用 set_obj_x ，这个意思就是 把src-c里的.c名字变为out/*.o名字
$(eval $(foreach f,$(EXTRA_SRC),$(call add_newline,vpath $(notdir $f) $(dir $f))))
#这个makefile函数 调用add_newline 只有$1，那么这句话的意思是设置vpath变量
#执行完成后vpath (exter_src)文件 目录 vpath的意思是到指定目录下去找extra_src文件。
$(eval $(foreach d,$(SRC_DIR),$(foreach i,$(SUFFIX),$(call add_newline,vpath %.$i $d))))

all_objs = $(foreach i,$(SUFFIX),$(obj-$i))
#这里 把obj-c obj-cc obj-cxx obj-cxx定义的.o文件汇集
all_srcs = $(foreach i,$(SUFFIX),$(src-$i))
#同理all_objs

CFLAGS       += $(EXTRA_CFLAGS) $(WARNINGS) $(OPTIMIZE) $(DEFS)
TARGET_TYPE := $(strip $(TARGET_TYPE))

ifeq ($(filter $(TARGET_TYPE),so ar app),)
	$(error Unexpected TARGET_TYPE `$(TARGET_TYPE)`)
endif



#定义伪目标
#如果编写一个规则，并不产生目标文件，则其命令在每次make 该目标时都执行
#
PHONY = romfs .mkdir clean

romfs: .mkdir $(TARGET)

define cmd_o
$$(obj-$1): $2%.o: %.$1  $(MAKEFILE_LIST)
	$(GCC) $(inc_dir) -Wp,-MT,$$@ -Wp,-MMD,$$@.d $(CFLAGS) -c -o $$@ $$<
endef
$(eval $(foreach i,$(SUFFIX),$(call cmd_o,$i,$(prefix_objdir))))
#这个函数是执行cmd_o , 
#执行完之后cmd_o变成：
# $(obj-c):out/%.o: %.c %(MAKEFILE_LIST
#	$(GCC) $(inc_dir) -Wp, -MT, $$@ -Wp,-MMD,$$@.d $(CFLGAS) -c -o $$@ $$<
#这个是典型makefile的静态模式规则。
#这里$(obj-c)里的.o 和$2%.o里的.o都依赖各自对应的.c
#会出现相应$(SUFFIX)中的obj-c obj-cxx obj-cpp
#这句意思就是(obj-c)里的.o和$(prefix_objdir)%.o都依赖于各自对应的.c
#它其实和%.o:%.c类似，只不过是指定了具体哪个目录下的.c对应与哪个目录下的.o
#动作就是 执行gcc 编译成对应的.o文件
#$@--目标文件，$^--所有的依赖文件，$<--第一个依赖文件。
#这个目标，执行次数就是.c文件的个数， $@生成目标， $$< 目标依赖的第一个文件。

#判断目标类型，根据目标类型决定链接链接参数

ifeq ($(TARGET_TYPE),so)
CFLAGS  += -fpic -shared -m32
LDFLAGS += -shared -m32
endif

ifeq ($(TARGET_TYPE),ar)
$(TARGET): AR := $(CROSS_COMPILE)ar
$(TARGET): $(all_objs)
	rm -f $@
	$(AR) rcvs $@ $(all_objs)
else
$(TARGET): LD = $(if $(strip $(src-cpp) $(src-cc) $(src-cxx)),$(G++),$(GCC))
$(TARGET): $(all_objs)
	$(LD) $(all_objs) $(LDFLAGS) -o $@
endif

.mkdir:
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi
clean:
	rm -f $(prefix_objdir)*.o $(prefix_objdir)*.d $(TARGET)
install:
	cp *.so /lib
#这里 include 所有all_objs里所有匹配%.o.d文件，意思是如果c文件包含的include文件更新了那么make就会更新.o文件，重新编译链接。但第一次编译时并没有任何文件，因为-include是在命令执行之前执行的操作。
-include $(patsubst %.o,%.o.d,$(all_objs))

.PHONY: $(PHONY)
