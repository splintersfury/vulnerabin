undefined4 * __cdecl
FUN_100073b0(undefined4 param_1,undefined4 *param_2,undefined4 param_3,int *param_4,
            undefined4 param_5,int param_6)

{
  int iVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  
  if (param_6 != 0) {
    do {
      if (param_4 == (int *)0x0) {
LAB_1000740d:
        param_3 = CONCAT31(param_3._1_3_,1);
      }
      else {
        if (*(int *)param_4[8] == 0) {
LAB_100073fa:
          uVar3 = (**(code **)(*param_4 + 0xc))(param_5);
        }
        else {
          iVar1 = *(int *)param_4[0xc];
          if (iVar1 < 1) goto LAB_100073fa;
          *(int *)param_4[0xc] = iVar1 + -1;
          puVar2 = *(undefined2 **)param_4[8];
          *(undefined2 **)param_4[8] = puVar2 + 1;
          *puVar2 = (short)param_5;
          uVar3 = param_5;
        }
        if ((short)uVar3 == -1) goto LAB_1000740d;
      }
      param_6 = param_6 + -1;
    } while (param_6 != 0);
  }
  *param_2 = param_3;
  param_2[1] = param_4;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007430 @ 10007430