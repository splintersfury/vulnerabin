int * __thiscall FUN_10009750(void *this,int *param_1,ushort *param_2)

{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  int local_1c [2];
  int local_14;
  int *local_10;
  uint local_c;
  uint local_8;
  
  local_10 = (int *)this;
  FUN_10009bc0(this,local_1c,param_2);
  if (*(char *)(local_14 + 0xd) == '\0') {
    puVar3 = (ushort *)(local_14 + 0x10);
    local_8 = *(uint *)(local_14 + 0x20);
    if (7 < *(uint *)(local_14 + 0x24)) {
      puVar3 = *(ushort **)puVar3;
    }
    local_c = *(uint *)(param_2 + 8);
    if (7 < *(uint *)(param_2 + 10)) {
      param_2 = *(ushort **)param_2;
    }
    uVar1 = local_c;
    if (local_8 < local_c) {
      uVar1 = local_8;
    }
    iVar2 = FUN_10009c60(param_2,puVar3,uVar1);
    if (iVar2 == 0) {
      if (local_8 <= local_c) {
LAB_100097cc:
        *param_1 = local_14;
        return param_1;
      }
    }
    else if (-1 < iVar2) goto LAB_100097cc;
  }
  *param_1 = *local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100097e0 @ 100097e0