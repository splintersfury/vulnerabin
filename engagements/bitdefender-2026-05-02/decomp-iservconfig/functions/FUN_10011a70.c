void __thiscall FUN_10011a70(void *this,int param_1,int param_2)

{
  undefined4 uVar1;
  int local_14;
  undefined4 *local_10;
  int local_c;
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_c = param_1;
  *(bool *)((int)this + 0x48) = param_2 == 1;
  local_10 = (undefined4 *)((int)this + 4);
  *(undefined4 **)((int)this + 0xc) = local_10;
  *(undefined1 *)((int)this + 0x3d) = 0;
  *(undefined4 **)((int)this + 0x10) = (undefined4 *)((int)this + 8);
  *(undefined4 **)((int)this + 0x20) = (undefined4 *)((int)this + 0x18);
  *(undefined4 **)((int)this + 0x1c) = (undefined4 *)((int)this + 0x14);
  *(undefined4 **)((int)this + 0x2c) = (undefined4 *)((int)this + 0x24);
  *(undefined4 **)((int)this + 0x30) = (undefined4 *)((int)this + 0x28);
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x28) = 0;
  *local_10 = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x24) = 0;
  if (param_1 != 0) {
    local_14 = 0;
    local_c = 0;
    local_10 = (undefined4 *)0x0;
    __get_stream_buffer_pointers(param_1,&local_14,&local_c,(int *)&local_10);
    *(int *)((int)this + 0xc) = local_14;
    *(int *)((int)this + 0x10) = local_14;
    *(int *)((int)this + 0x1c) = local_c;
    *(int *)((int)this + 0x20) = local_c;
    *(undefined4 **)((int)this + 0x2c) = local_10;
    *(undefined4 **)((int)this + 0x30) = local_10;
  }
  uVar1 = DAT_1006b630;
  *(undefined4 *)((int)this + 0x44) = DAT_1006b634;
  *(int *)((int)this + 0x4c) = param_1;
  *(undefined4 *)((int)this + 0x40) = uVar1;
  *(undefined4 *)((int)this + 0x38) = 0;
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: operator++ @ 10011b80

/* Library Function - Single Match
    public: class std::_Tree_unchecked_const_iterator<class std::_Tree_val<struct
   std::_Tree_simple_types<unsigned int> >,struct std::_Iterator_base0> & __thiscall
   std::_Tree_unchecked_const_iterator<class std::_Tree_val<struct std::_Tree_simple_types<unsigned
   int> >,struct std::_Iterator_base0>::operator++(void)
   
   Library: Visual Studio 2019 Release */

_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
* __thiscall
std::
_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
::operator++(_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
             *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  
  iVar2 = *(int *)this;
  piVar3 = *(int **)(iVar2 + 8);
  if (*(char *)((int)piVar3 + 0xd) != '\0') {
    cVar1 = *(char *)(*(int *)(iVar2 + 4) + 0xd);
    iVar5 = *(int *)(iVar2 + 4);
    while ((cVar1 == '\0' && (iVar2 == *(int *)(iVar5 + 8)))) {
      *(int *)this = iVar5;
      cVar1 = *(char *)(*(int *)(iVar5 + 4) + 0xd);
      iVar2 = iVar5;
      iVar5 = *(int *)(iVar5 + 4);
    }
    *(int *)this = iVar5;
    return this;
  }
  cVar1 = *(char *)(*piVar3 + 0xd);
  piVar4 = (int *)*piVar3;
  while (cVar1 == '\0') {
    cVar1 = *(char *)(*piVar4 + 0xd);
    piVar3 = piVar4;
    piVar4 = (int *)*piVar4;
  }
  *(int **)this = piVar3;
  return this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10011be0 @ 10011be0