int * __thiscall FUN_10021fc0(void *this,int *param_1)

{
  int iVar1;
  code *pcVar2;
  int *piVar3;
  int *local_1c;
  int local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004feed;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10023ea0(this,(int *)&local_1c,param_1);
  if ((*(char *)((int)local_14 + 0xd) != '\0') || (*param_1 < local_14[4])) {
    if (*(int *)((int)this + 4) == 0x5d1745d) {
      FUN_10001840();
      pcVar2 = (code *)swi(3);
      piVar3 = (int *)(*pcVar2)();
      return piVar3;
    }
                    /* WARNING: Load size is inaccurate */
    iVar1 = *this;
    local_8 = 0;
    piVar3 = (int *)operator_new(0x2c);
    piVar3[4] = *param_1;
    piVar3[5] = 0;
    piVar3[9] = 0;
    piVar3[10] = 0xf;
    *piVar3 = iVar1;
    piVar3[1] = iVar1;
    piVar3[2] = iVar1;
    *(undefined2 *)(piVar3 + 3) = 0;
    local_14 = Insert_node(this,local_1c,local_18,piVar3);
  }
  ExceptionList = local_10;
  return local_14 + 5;
}


// FUNCTION_END

// FUNCTION_START: FUN_10022090 @ 10022090