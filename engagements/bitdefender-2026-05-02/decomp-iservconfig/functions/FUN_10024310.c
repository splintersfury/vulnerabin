int * __fastcall FUN_10024310(int *param_1,uint *param_2)

{
  uint *puVar1;
  code *pcVar2;
  int *piVar3;
  undefined4 ****ppppuVar4;
  undefined4 ***local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 ***local_28 [4];
  undefined4 local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100500ed;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = param_2 + 4;
  if (7 < param_2[5]) {
    param_2 = (uint *)*param_2;
  }
  local_28[0] = (undefined4 ****)0x0;
  local_18 = 0;
  local_14 = 7;
  if (param_2 != (uint *)(*puVar1 * 2 + (int)param_2)) {
    FUN_10001d40(local_28,param_2,(int)(*puVar1 * 2) >> 1);
  }
  local_8 = 0;
  local_2c = 0x5c0022;
  local_34 = local_28;
  if (7 < local_14) {
    local_34 = local_28[0];
  }
  local_30 = local_18;
  piVar3 = FUN_10024420(param_1,&local_34);
  if (7 < local_14) {
    ppppuVar4 = (undefined4 ****)local_28[0];
    if (0xfff < local_14 * 2 + 2) {
      ppppuVar4 = (undefined4 ****)local_28[0][-1];
      if (0x1f < (uint)((int)local_28[0] + (-4 - (int)ppppuVar4))) {
        FUN_10032f7f();
        pcVar2 = (code *)swi(3);
        piVar3 = (int *)(*pcVar2)();
        return piVar3;
      }
    }
    FUN_1002e346(ppppuVar4);
  }
  ExceptionList = local_10;
  return piVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_10024400 @ 10024400