void __fastcall FUN_10002c40(void *param_1)

{
  undefined8 *puVar1;
  _Locimp *p_Var2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004da60;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)((int)param_1 + 0x30) = 0;
  *(undefined4 *)((int)param_1 + 8) = 0;
  *(undefined4 *)((int)param_1 + 0x10) = 0;
  *(undefined4 *)((int)param_1 + 0x14) = 0x201;
  *(undefined4 *)((int)param_1 + 0x18) = 6;
  *(undefined4 *)((int)param_1 + 0x1c) = 0;
  *(undefined4 *)((int)param_1 + 0x20) = 0;
  *(undefined4 *)((int)param_1 + 0x24) = 0;
  *(undefined4 *)((int)param_1 + 0x28) = 0;
  *(undefined4 *)((int)param_1 + 0x2c) = 0;
  FUN_10002bd0(param_1,0,'\0');
  puVar1 = (undefined8 *)operator_new(8);
  *puVar1 = 0;
  local_8 = 0;
  p_Var2 = std::locale::_Init(true);
  *(_Locimp **)((int)puVar1 + 4) = p_Var2;
  *(undefined8 **)((int)param_1 + 0x30) = puVar1;
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002d00 @ 10002d00