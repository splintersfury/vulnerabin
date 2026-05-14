void FUN_14001bdb0(longlong *param_1,fpos_t *param_2,longlong param_3,int param_4)

{
  longlong lVar1;
  longlong lVar2;
  fpos_t fVar3;
  char cVar4;
  int iVar5;
  undefined1 auStack_58 [32];
  fpos_t local_38;
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStack_58;
  if (((*(longlong **)param_1[7] == param_1 + 0xe) && (param_4 == 1)) && (param_1[0xd] == 0)) {
    param_3 = param_3 + -1;
  }
  if (param_1[0x10] != 0) {
    cVar4 = FUN_14001d7d0(param_1);
    if (cVar4 != '\0') {
      if ((param_3 != 0) || (param_4 != 1)) {
        iVar5 = common_fseek(param_1[0x10],param_3,param_4);
        if (iVar5 != 0) goto LAB_14001be84;
      }
      iVar5 = fgetpos((FILE *)param_1[0x10],&local_38);
      if (iVar5 == 0) {
        if (*(longlong **)param_1[3] == param_1 + 0xe) {
          lVar1 = param_1[0x11];
          lVar2 = param_1[0x12];
          *(longlong *)param_1[3] = lVar1;
          *(longlong *)param_1[7] = lVar1;
          *(int *)param_1[10] = (int)lVar2 - (int)lVar1;
        }
        fVar3 = *(fpos_t *)((longlong)param_1 + 0x74);
        *param_2 = local_38;
        param_2[2] = fVar3;
        param_2[1] = 0;
        goto LAB_14001be99;
      }
    }
  }
LAB_14001be84:
  *param_2 = -1;
  param_2[1] = 0;
  param_2[2] = 0;
LAB_14001be99:
  FUN_14002f160(local_30 ^ (ulonglong)auStack_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001bec0 @ 14001bec0