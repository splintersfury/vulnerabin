uint * __thiscall FUN_1000b650(void *this,uint *param_1)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  uint *puVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint *puVar9;
  void *pvVar10;
  uint uVar11;
  uint *local_c;
  uint *local_8;
  
  uVar11 = param_1[5];
  puVar9 = param_1;
  if (7 < uVar11) {
    puVar9 = (uint *)*param_1;
  }
  uVar1 = param_1[4];
  iVar3 = uVar1 * 2;
  if ((iVar3 >> 1 < 2) || (0x19 < (*puVar9 & 0xffffffdf) - 0x3a0041)) {
    puVar4 = FUN_1000b570(puVar9,(uint *)(iVar3 + (int)puVar9));
    uVar11 = param_1[5];
    if (puVar9 != puVar4) goto LAB_1000b774;
  }
  else if ((2 < iVar3 >> 1) && (((short)puVar9[1] == 0x5c || ((short)puVar9[1] == 0x2f)))) {
LAB_1000b774:
    if ((uint *)this == param_1) {
      return (uint *)this;
    }
    goto LAB_1000b745;
  }
  local_c = (uint *)this;
  if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
    local_c = *this;
  }
  local_8 = param_1;
  puVar9 = (uint *)((int)local_c + *(int *)((int)this + 0x10) * 2);
  if (7 < uVar11) {
    local_8 = (uint *)*param_1;
  }
  puVar4 = FUN_1000b570(local_c,puVar9);
  puVar5 = FUN_1000b570(local_8,(uint *)(iVar3 + (int)local_8));
  if (local_8 != puVar5) {
    uVar6 = (int)puVar5 - (int)local_8 >> 1;
    uVar7 = (int)puVar4 - (int)local_c >> 1;
    uVar11 = uVar7;
    if (uVar6 < uVar7) {
      uVar11 = uVar6;
    }
    iVar8 = FUN_10009c60((ushort *)local_c,(ushort *)local_8,uVar11);
    if (((iVar8 != 0) || (uVar7 < uVar6)) || (uVar6 < uVar7)) {
      if ((uint *)this == param_1) {
        return (uint *)this;
      }
      uVar11 = param_1[5];
LAB_1000b745:
      if (7 < uVar11) {
        param_1 = (uint *)*param_1;
      }
      FUN_10001d40(this,param_1,uVar1);
      return (uint *)this;
    }
  }
  if ((puVar5 == (uint *)(iVar3 + (int)local_8)) ||
     (((short)*puVar5 != 0x5c && ((short)*puVar5 != 0x2f)))) {
    if (puVar4 == puVar9) {
      if ((int)((int)puVar4 - (int)local_c & 0xfffffffeU) < 6) goto LAB_1000b7e6;
    }
    else if ((*(short *)((int)puVar9 + -2) == 0x5c) || (*(short *)((int)puVar9 + -2) == 0x2f))
    goto LAB_1000b7e6;
    FUN_10005b60(this,0x5c);
  }
  else {
    uVar11 = (int)puVar4 - (int)local_c >> 1;
    if (*(uint *)((int)this + 0x10) < uVar11) {
      FUN_10007f70();
      pcVar2 = (code *)swi(3);
      puVar9 = (uint *)(*pcVar2)();
      return puVar9;
    }
    pvVar10 = this;
    if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
      pvVar10 = *this;
    }
    *(uint *)((int)this + 0x10) = uVar11;
    *(undefined2 *)((int)pvVar10 + uVar11 * 2) = 0;
  }
LAB_1000b7e6:
  FUN_10005d60(this,puVar5,(iVar3 + (int)local_8) - (int)puVar5 >> 1);
  return (uint *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b810 @ 1000b810