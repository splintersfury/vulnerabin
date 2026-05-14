int * __thiscall FUN_10014a40(void *this,int *param_1,byte *param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  byte *pbVar5;
  uint uVar6;
  byte *pbVar7;
  undefined4 *puVar8;
  
                    /* WARNING: Load size is inaccurate */
  iVar2 = *this;
  puVar8 = *(undefined4 **)(iVar2 + 4);
  *param_1 = (int)puVar8;
  cVar1 = *(char *)((int)puVar8 + 0xd);
  param_1[1] = 0;
  param_1[2] = iVar2;
  if (cVar1 == '\0') {
    uVar3 = *(uint *)(param_2 + 0x14);
    uVar4 = *(uint *)(param_2 + 0x10);
    do {
      *param_1 = (int)puVar8;
      pbVar7 = (byte *)(puVar8 + 4);
      pbVar5 = param_2;
      if (0xf < uVar3) {
        pbVar5 = *(byte **)param_2;
      }
      if (0xf < (uint)puVar8[9]) {
        pbVar7 = *(byte **)pbVar7;
      }
      uVar6 = FUN_100148a0(pbVar7,puVar8[8],pbVar5,uVar4);
      if (-1 < (int)uVar6) {
        param_1[2] = (int)puVar8;
        puVar8 = (undefined4 *)*puVar8;
      }
      else {
        puVar8 = (undefined4 *)puVar8[2];
      }
      param_1[1] = (uint)(-1 < (int)uVar6);
    } while (*(char *)((int)puVar8 + 0xd) == '\0');
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014ac0 @ 10014ac0