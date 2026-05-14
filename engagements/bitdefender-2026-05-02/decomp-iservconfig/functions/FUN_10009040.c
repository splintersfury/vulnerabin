undefined4 FUN_10009040(undefined4 param_1,int param_2)

{
  int *piVar1;
  undefined4 *_Dst;
  void *pvVar2;
  int *piVar3;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  piVar3 = DAT_1006b6a8;
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e184;
  local_10 = ExceptionList;
  if (param_2 == 0) {
    DAT_1006b6a8 = (undefined4 *)0x0;
    if (piVar3 == (int *)0x0) {
      DAT_1006b6a8 = (int *)0x0;
      return 1;
    }
    ExceptionList = &local_10;
    __Mtx_destroy_in_situ((int)(piVar3 + 3));
    FUN_10009af0(piVar3,*(int **)(*piVar3 + 4));
    FUN_1002e346((void *)*piVar3);
  }
  else {
    if (param_2 != 1) {
      return 1;
    }
    ExceptionList = &local_10;
    _Dst = (undefined4 *)operator_new(0x3c);
    local_8 = 0;
    _memset(_Dst,0,0x3c);
    *_Dst = 0;
    _Dst[1] = 0;
    pvVar2 = operator_new(0x2c);
    *(void **)pvVar2 = pvVar2;
    *(void **)((int)pvVar2 + 4) = pvVar2;
    *(void **)((int)pvVar2 + 8) = pvVar2;
    *(undefined2 *)((int)pvVar2 + 0xc) = 0x101;
    *_Dst = pvVar2;
    _Dst[2] = 0;
    __Mtx_init_in_situ(_Dst + 3,2);
    piVar3 = DAT_1006b6a8;
    if (DAT_1006b6a8 == (int *)0x0) {
      DAT_1006b6a8 = _Dst;
      ExceptionList = local_10;
      return 1;
    }
    piVar1 = DAT_1006b6a8 + 3;
    DAT_1006b6a8 = _Dst;
    __Mtx_destroy_in_situ((int)piVar1);
    FUN_10009af0(piVar3,*(int **)(*piVar3 + 4));
    FUN_1002e346((void *)*piVar3);
  }
  FUN_1002e346(piVar3);
  ExceptionList = local_10;
  return 1;
}


// FUNCTION_END

// FUNCTION_START: BdCreateObject @ 10009160