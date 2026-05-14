int * __thiscall FUN_10022090(void *this,int *param_1)

{
  int iVar1;
  code *pcVar2;
  int *piVar3;
  int *local_24;
  int local_20;
  int *local_1c;
  void *local_18;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004ff1d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10023ea0(this,(int *)&local_24,param_1);
  if ((*(char *)((int)local_1c + 0xd) != '\0') || (*param_1 < local_1c[4])) {
    if (*(int *)((int)this + 4) == 0x5d1745d) {
      FUN_10001840();
      pcVar2 = (code *)swi(3);
      piVar3 = (int *)(*pcVar2)();
      return piVar3;
    }
                    /* WARNING: Load size is inaccurate */
    iVar1 = *this;
    local_8 = 0;
    local_14 = 0;
    local_18 = this;
    piVar3 = (int *)operator_new(0x2c);
    local_14 = 0;
    piVar3[4] = *param_1;
    piVar3[5] = 0;
    piVar3[9] = 0;
    piVar3[10] = 7;
    *piVar3 = iVar1;
    piVar3[1] = iVar1;
    piVar3[2] = iVar1;
    *(undefined2 *)(piVar3 + 3) = 0;
    FUN_10023be0((int)&local_18);
    local_1c = Insert_node(this,local_24,local_20,piVar3);
  }
  ExceptionList = local_10;
  return local_1c + 5;
}


// FUNCTION_END

// FUNCTION_START: FUN_10022170 @ 10022170