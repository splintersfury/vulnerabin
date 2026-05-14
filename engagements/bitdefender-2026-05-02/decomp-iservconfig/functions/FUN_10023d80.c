void __thiscall FUN_10023d80(void *this,int *param_1,byte *param_2)

{
  byte bVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  byte *pbVar5;
  uint uVar6;
  byte *pbVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  
                    /* WARNING: Load size is inaccurate */
  puVar3 = *this;
  cVar2 = *(char *)((int)puVar3[1] + 0xd);
  puVar4 = puVar3;
  puVar8 = (undefined4 *)puVar3[1];
  while (cVar2 == '\0') {
    pbVar7 = (byte *)(puVar8 + 4);
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      pbVar5 = pbVar5 + 1;
    } while (bVar1 != 0);
    if (0xf < (uint)puVar8[9]) {
      pbVar7 = *(byte **)pbVar7;
    }
    uVar6 = FUN_100148a0(pbVar7,puVar8[8],param_2,(int)pbVar5 - (int)(param_2 + 1));
    if ((int)uVar6 < 0) {
      puVar9 = (undefined4 *)puVar8[2];
      puVar8 = puVar4;
    }
    else {
      puVar9 = (undefined4 *)*puVar8;
    }
    puVar4 = puVar8;
    puVar8 = puVar9;
    cVar2 = *(char *)((int)puVar9 + 0xd);
  }
  if (*(char *)((int)puVar4 + 0xd) == '\0') {
    pbVar7 = (byte *)(puVar4 + 4);
    pbVar5 = param_2;
    do {
      bVar1 = *pbVar5;
      pbVar5 = pbVar5 + 1;
    } while (bVar1 != 0);
    if (0xf < (uint)puVar4[9]) {
      pbVar7 = *(byte **)pbVar7;
    }
    uVar6 = FUN_100148a0(pbVar7,puVar4[8],param_2,(int)pbVar5 - (int)(param_2 + 1));
    if ((int)uVar6 < 1) {
      *param_1 = (int)puVar4;
      return;
    }
  }
  *param_1 = (int)puVar3;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023e40 @ 10023e40