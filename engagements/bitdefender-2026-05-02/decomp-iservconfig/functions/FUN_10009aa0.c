void __fastcall FUN_10009aa0(int param_1)

{
  int *piVar1;
  _Mtx_internal_imp_t *p_Var2;
  code *pcVar3;
  int iVar4;
  
  p_Var2 = *(_Mtx_internal_imp_t **)(param_1 + 4);
  iVar4 = __Mtx_lock(p_Var2);
  if (iVar4 == 0) {
    piVar1 = (int *)(param_1 + 8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      piVar1 = *(int **)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0xc) = 0;
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 0x4c))(1);
      }
    }
    __Mtx_unlock((int)p_Var2);
    return;
  }
  FUN_1002d2dd(iVar4);
  pcVar3 = (code *)swi(3);
  (*pcVar3)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009af0 @ 10009af0