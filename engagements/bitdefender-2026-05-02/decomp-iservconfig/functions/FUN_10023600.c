undefined4 * __fastcall FUN_10023600(undefined4 *param_1,undefined4 *param_2,_Facet_base *param_3)

{
  void *pvVar1;
  undefined2 uVar2;
  uint uVar3;
  int *piVar4;
  undefined4 *puVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  pvVar1 = ExceptionList;
  puStack_c = &LAB_1005000d;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  if ((uint)param_2[5] < 8) {
    puVar5 = (undefined4 *)((int)param_2 + param_2[4] * 2);
  }
  else {
    piVar4 = param_2 + 4;
    param_2 = (undefined4 *)*param_2;
    puVar5 = (undefined4 *)((int)param_2 + *piVar4 * 2);
  }
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  local_8 = 0;
  if (param_2 != puVar5) {
    do {
      uVar2 = *(undefined2 *)param_2;
      piVar4 = (int *)FUN_10006410(param_3);
      uVar2 = (**(code **)(*piVar4 + 0x20))(uVar2,uVar3);
      FUN_10005b60(param_1,uVar2);
      param_2 = (undefined4 *)((int)param_2 + 2);
    } while (param_2 != puVar5);
    ExceptionList = local_10;
    return param_1;
  }
  ExceptionList = pvVar1;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100236d0 @ 100236d0