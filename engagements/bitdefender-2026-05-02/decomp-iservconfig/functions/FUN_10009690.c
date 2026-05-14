void __fastcall FUN_10009690(int *param_1)

{
  _Mtx_internal_imp_t *p_Var1;
  char cVar2;
  code *pcVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  
  p_Var1 = (_Mtx_internal_imp_t *)(param_1 + 3);
  iVar5 = __Mtx_lock(p_Var1);
  if (iVar5 != 0) {
    FUN_1002d2dd(iVar5);
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  piVar7 = param_1 + 2;
  *piVar7 = *piVar7 + -1;
  if (*piVar7 == 0) {
    __Mtx_unlock((int)p_Var1);
    piVar7 = (int *)*param_1;
    piVar6 = (int *)*piVar7;
    if (piVar6 != piVar7) {
      do {
        (**(code **)(*(int *)piVar6[10] + 8))();
        piVar7 = (int *)piVar6[2];
        if (*(char *)((int)piVar7 + 0xd) == '\0') {
          cVar2 = *(char *)(*piVar7 + 0xd);
          piVar6 = piVar7;
          piVar7 = (int *)*piVar7;
          while (cVar2 == '\0') {
            cVar2 = *(char *)(*piVar7 + 0xd);
            piVar6 = piVar7;
            piVar7 = (int *)*piVar7;
          }
        }
        else {
          cVar2 = *(char *)(piVar6[1] + 0xd);
          piVar4 = (int *)piVar6[1];
          piVar7 = piVar6;
          while ((piVar6 = piVar4, cVar2 == '\0' && (piVar7 == (int *)piVar6[2]))) {
            cVar2 = *(char *)(piVar6[1] + 0xd);
            piVar4 = (int *)piVar6[1];
            piVar7 = piVar6;
          }
        }
        piVar7 = (int *)*param_1;
      } while (piVar6 != piVar7);
    }
    FUN_10009af0(param_1,(int *)piVar7[1]);
    piVar7[1] = (int)piVar7;
    *piVar7 = (int)piVar7;
    piVar7[2] = (int)piVar7;
    param_1[1] = 0;
    FUN_10006030();
    return;
  }
  __Mtx_unlock((int)p_Var1);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009750 @ 10009750