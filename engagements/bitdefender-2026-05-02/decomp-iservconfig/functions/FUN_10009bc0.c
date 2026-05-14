int * __thiscall FUN_10009bc0(void *this,int *param_1,ushort *param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  ushort *puVar5;
  undefined4 *puVar6;
  ushort *local_8;
  
                    /* WARNING: Load size is inaccurate */
  puVar6 = *(undefined4 **)(*this + 4);
  *param_1 = (int)puVar6;
  param_1[1] = 0;
                    /* WARNING: Load size is inaccurate */
  param_1[2] = *this;
  cVar1 = *(char *)((int)puVar6 + 0xd);
  do {
    if (cVar1 != '\0') {
      return param_1;
    }
    *param_1 = (int)puVar6;
    puVar5 = (ushort *)(puVar6 + 4);
    local_8 = param_2;
    if (7 < *(uint *)(param_2 + 10)) {
      local_8 = *(ushort **)param_2;
    }
    uVar2 = puVar6[8];
    if (7 < (uint)puVar6[9]) {
      puVar5 = *(ushort **)puVar5;
    }
    uVar3 = uVar2;
    if (*(uint *)(param_2 + 8) < uVar2) {
      uVar3 = *(uint *)(param_2 + 8);
    }
    iVar4 = FUN_10009c60(puVar5,local_8,uVar3);
    if (iVar4 == 0) {
      if (uVar2 < *(uint *)(param_2 + 8)) goto LAB_10009c51;
LAB_10009c2c:
      param_1[1] = 1;
      param_1[2] = (int)puVar6;
      puVar6 = (undefined4 *)*puVar6;
    }
    else {
      if (-1 < iVar4) goto LAB_10009c2c;
LAB_10009c51:
      param_1[1] = 0;
      puVar6 = (undefined4 *)puVar6[2];
    }
    cVar1 = *(char *)((int)puVar6 + 0xd);
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_10009c60 @ 10009c60