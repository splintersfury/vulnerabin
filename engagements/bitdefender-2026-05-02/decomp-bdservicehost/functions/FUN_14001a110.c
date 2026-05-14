undefined8 * FUN_14001a110(undefined8 *param_1,char *param_2,LPCSTR **param_3,LPCSTR ***param_4)

{
  char *pcVar1;
  longlong *plVar2;
  undefined8 *puVar3;
  LPCSTR ******pppppppCVar4;
  LPCSTR *****local_b0 [2];
  undefined8 local_a0;
  ulonglong local_98;
  undefined8 *local_90;
  undefined8 local_88 [7];
  longlong local_50 [4];
  undefined8 local_30 [5];
  
  local_90 = param_1;
  pcVar1 = (char *)FUN_14001cdf0(param_2,param_3,param_3,param_4);
  local_a0 = 0;
  local_98 = 0xf;
  local_b0[0] = (LPCSTR *****)0x0;
  if (*pcVar1 != '\x03') {
LAB_14001a1fa:
    pcVar1 = FUN_14001ddd0(pcVar1);
    plVar2 = FUN_14000e950(local_50,(undefined8 *)pcVar1);
    puVar3 = FUN_140011fa0(local_30,(undefined8 *)"type must be string, but is ",plVar2,param_4);
    FUN_1400190c0(local_88,0x12e,puVar3);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_88,(ThrowInfo *)&DAT_140077cc0);
  }
  pppppppCVar4 = *(LPCSTR *******)(pcVar1 + 8);
  if (local_b0 != pppppppCVar4) {
    param_3 = (LPCSTR **)pppppppCVar4[2];
    if ((LPCSTR *****)0xf < pppppppCVar4[3]) {
      pppppppCVar4 = (LPCSTR ******)*pppppppCVar4;
    }
    FUN_1400106a0((longlong *)local_b0,pppppppCVar4,(ulonglong)param_3);
  }
  param_4 = (LPCSTR ***)local_b0;
  if (0xf < local_98) {
    param_4 = (LPCSTR ***)local_b0[0];
  }
  FUN_1400180b0(param_1,pppppppCVar4,param_3,(LPCSTR)param_4);
  if (0xf < local_98) {
    if ((0xfff < local_98 + 1) &&
       (pcVar1 = (char *)(local_98 + 0x28),
       0x1f < (ulonglong)((longlong)local_b0[0] + (-8 - (longlong)local_b0[0][-1])))) {
      FUN_140035d28();
      goto LAB_14001a1fa;
    }
    FUN_14002f180();
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001a250 @ 14001a250

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */