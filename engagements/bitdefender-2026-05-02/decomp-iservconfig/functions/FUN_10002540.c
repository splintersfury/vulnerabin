_Lockit * __thiscall FUN_10002540(void *this,char *param_1)

{
  code *pcVar1;
  _Lockit *p_Var2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004da1f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  std::_Lockit::_Lockit((_Lockit *)this,0);
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined1 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined1 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined2 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined2 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined1 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined1 *)((int)this + 0x30) = 0;
  local_8 = 6;
  if (param_1 != (char *)0x0) {
    std::_Locinfo::_Locinfo_ctor((_Locinfo *)this,param_1);
    ExceptionList = local_10;
    return (_Lockit *)this;
  }
  FUN_1002c894("bad locale name");
  pcVar1 = (code *)swi(3);
  p_Var2 = (_Lockit *)(*pcVar1)();
  return p_Var2;
}


// FUNCTION_END

// FUNCTION_START: FUN_100025f0 @ 100025f0