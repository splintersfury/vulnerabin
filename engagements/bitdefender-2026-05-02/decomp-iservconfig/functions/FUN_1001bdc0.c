int * __thiscall FUN_1001bdc0(void *this,undefined4 *param_1,int param_2,undefined4 param_3)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004f795;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  piVar3 = *this;
  if (*(char *)((int)param_1 + 0xd) == '\0') {
    local_8 = 0;
    piVar1 = (int *)operator_new(0x38);
    FUN_100056d0(piVar1 + 4,param_1 + 4);
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_10011220(piVar1 + 10,(undefined1 *)(param_1 + 10));
    *piVar1 = (int)piVar3;
    piVar1[2] = (int)piVar3;
    *(undefined2 *)(piVar1 + 3) = 0;
    piVar1[1] = param_2;
    *(undefined1 *)(piVar1 + 3) = *(undefined1 *)(param_1 + 3);
    local_8 = 2;
    if (*(char *)((int)piVar3 + 0xd) != '\0') {
      piVar3 = piVar1;
    }
    piVar2 = FUN_1001bdc0(this,(undefined4 *)*param_1,(int)piVar1,param_3);
    *piVar1 = (int)piVar2;
    piVar2 = FUN_1001bdc0(this,(undefined4 *)param_1[2],(int)piVar1,param_3);
    piVar1[2] = (int)piVar2;
  }
  ExceptionList = local_10;
  return piVar3;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001beb6 @ 1001beb6