undefined4 __thiscall
FUN_100098f0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int *param_5)

{
  int **ppiVar1;
  _Mtx_internal_imp_t *p_Var2;
  code *pcVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  void *pvVar7;
  int *piVar8;
  undefined4 uVar9;
  int *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e22d;
  local_10 = ExceptionList;
  uVar4 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  p_Var2 = *(_Mtx_internal_imp_t **)((int)this + 4);
  iVar5 = __Mtx_lock(p_Var2);
  if (iVar5 != 0) {
    FUN_1002d2dd(iVar5);
    pcVar3 = (code *)swi(3);
    uVar9 = (*pcVar3)();
    return uVar9;
  }
  local_8 = 0;
  if (*(int *)((int)this + 8) == 0) {
    local_8 = iVar5;
    piVar6 = (int *)operator_new(0x50);
    local_14 = piVar6;
    _memset(piVar6,0,0x50);
    *piVar6 = (int)ProductInfo::vftable;
    __Mtx_init_in_situ(piVar6 + 1,0x102);
    local_8._0_1_ = 2;
    piVar6[0xd] = 0;
    piVar8 = piVar6 + 0xe;
    *piVar8 = 0;
    piVar6[0xf] = 0;
    local_18 = piVar8;
    pvVar7 = operator_new(0x2c);
    *(void **)pvVar7 = pvVar7;
    *(void **)((int)pvVar7 + 4) = pvVar7;
    *(void **)((int)pvVar7 + 8) = pvVar7;
    *(undefined2 *)((int)pvVar7 + 0xc) = 0x101;
    *piVar8 = (int)pvVar7;
    local_8._0_1_ = 3;
    piVar6 = local_14 + 0x10;
    *piVar6 = 0;
    local_14[0x11] = 0;
    local_18 = piVar6;
    pvVar7 = operator_new(0x2c);
    *(void **)pvVar7 = pvVar7;
    *(void **)((int)pvVar7 + 4) = pvVar7;
    *(void **)((int)pvVar7 + 8) = pvVar7;
    *(undefined2 *)((int)pvVar7 + 0xc) = 0x101;
    *piVar6 = (int)pvVar7;
    local_8._0_1_ = 4;
    piVar6 = local_14 + 0x12;
    *piVar6 = 0;
    local_14[0x13] = 0;
    local_18 = piVar6;
    pvVar7 = operator_new(0x2c);
    local_8 = (uint)local_8._1_3_ << 8;
    *(void **)pvVar7 = pvVar7;
    *(void **)((int)pvVar7 + 4) = pvVar7;
    *(void **)((int)pvVar7 + 8) = pvVar7;
    *(undefined2 *)((int)pvVar7 + 0xc) = 0x101;
    *piVar6 = (int)pvVar7;
    ppiVar1 = (int **)((int)this + 0xc);
    piVar6 = local_14;
    if (ppiVar1 == &local_18) {
LAB_10009a25:
      (**(code **)(*piVar6 + 0x4c))(1);
    }
    else {
      piVar6 = *ppiVar1;
      *ppiVar1 = local_14;
      if (piVar6 != (int *)0x0) goto LAB_10009a25;
    }
    if (*ppiVar1 == (int *)0x0) {
      uVar9 = 0xe;
      goto LAB_10009a72;
    }
  }
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
  iVar5 = (**(code **)**(undefined4 **)((int)this + 0xc))(param_1,param_2,param_3,param_4,uVar4);
  *param_5 = iVar5;
  if (iVar5 == 0) {
    uVar9 = 0x490;
  }
  else {
    uVar9 = 0;
  }
LAB_10009a72:
  __Mtx_unlock((int)p_Var2);
  ExceptionList = local_10;
  return uVar9;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009aa0 @ 10009aa0