int * __thiscall
FUN_10013db0(void *this,int *param_1,undefined4 param_2,char *param_3,int param_4,int param_5)

{
  uint *puVar1;
  char cVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  
  iVar4 = FUN_10013f20(this,this,param_4,param_5);
  param_1[0] = 0;
  param_1[1] = 0;
                    /* WARNING: Load size is inaccurate */
  *param_1 = *this;
  param_1[1] = 0;
  if ((iVar4 < 0) && ((uint)param_1[1] < (uint)-iVar4)) {
    uVar5 = param_1[1] + iVar4;
    iVar4 = (~uVar5 >> 5) * -4 + -4;
  }
  else {
    uVar5 = param_1[1] + iVar4;
    iVar4 = (uVar5 >> 5) << 2;
  }
  *param_1 = *param_1 + iVar4;
  param_1[1] = uVar5 & 0x1f;
  puVar3 = (uint *)*param_1;
  uVar5 = param_1[1] + 1;
  uVar7 = uVar5 & 0x1f;
  puVar1 = puVar3 + (uVar5 >> 5);
  if ((puVar3 != puVar1) || (param_1[1] != uVar7)) {
    uVar5 = -1 << ((byte)param_1[1] & 0x1f);
    cVar2 = *param_3;
    if (puVar3 == puVar1) {
      uVar6 = 0xffffffff >> (0x20U - (char)uVar7 & 0x1f);
      uVar7 = 0;
      if (cVar2 != '\0') {
        uVar7 = uVar6;
      }
      *puVar3 = uVar7 & uVar5 | (~uVar6 | ~uVar5) & *puVar3;
      return param_1;
    }
    uVar6 = 0;
    if (cVar2 != '\0') {
      uVar6 = uVar5;
    }
    *puVar3 = uVar6 | *puVar3 & ~uVar5;
    iVar4 = 0;
    if (*param_3 != '\0') {
      iVar4 = 0xff;
    }
    _memset(puVar3 + 1,iVar4,(int)puVar1 - (int)(puVar3 + 1));
    if (uVar7 != 0) {
      uVar7 = 0xffffffff >> (0x20U - (char)uVar7 & 0x1f);
      uVar5 = 0;
      if (cVar2 != '\0') {
        uVar5 = uVar7;
      }
      *puVar1 = uVar5 | ~uVar7 & *puVar1;
    }
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10013f20 @ 10013f20

/* WARNING: Removing unreachable block (ram,0x10013fe0) */
/* WARNING: Removing unreachable block (ram,0x10013fe4) */
/* WARNING: Removing unreachable block (ram,0x10013fe8) */
/* WARNING: Removing unreachable block (ram,0x10013fea) */