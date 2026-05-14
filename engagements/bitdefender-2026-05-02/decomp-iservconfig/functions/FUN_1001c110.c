int __thiscall FUN_1001c110(void *this,uint *param_1,int param_2)

{
  uint *puVar1;
  uint *puVar2;
  byte bVar3;
  uint *puVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  uint uVar10;
  uint *puVar11;
  uint *local_10;
  
  local_10 = (uint *)this;
  if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
    local_10 = *this;
  }
  puVar1 = (uint *)((int)local_10 + *(int *)((int)this + 0x10) * 2);
  puVar4 = FUN_1000b570(local_10,puVar1);
  puVar2 = (uint *)((int)param_1 + param_2 * 2);
  puVar5 = FUN_1000b570(param_1,puVar2);
  uVar8 = (int)puVar4 - (int)local_10 >> 1;
  uVar6 = (int)puVar5 - (int)param_1 >> 1;
  uVar10 = uVar8;
  if (uVar6 < uVar8) {
    uVar10 = uVar6;
  }
  iVar7 = FUN_10009c60((ushort *)local_10,(ushort *)param_1,uVar10);
  if (iVar7 == 0) {
    if (uVar8 < uVar6) {
      return -1;
    }
    puVar9 = puVar4;
    if (uVar6 < uVar8) {
      return 1;
    }
    for (; (puVar11 = puVar5, puVar9 != puVar1 &&
           (((short)*puVar9 == 0x5c || ((short)*puVar9 == 0x2f))));
        puVar9 = (uint *)((int)puVar9 + 2)) {
    }
    for (; (puVar11 != puVar2 && (((short)*puVar11 == 0x5c || ((short)*puVar11 == 0x2f))));
        puVar11 = (uint *)((int)puVar11 + 2)) {
    }
    iVar7 = (uint)(puVar4 != puVar9) - (uint)(puVar5 != puVar11);
    if (iVar7 == 0) {
      iVar7 = (uint)(puVar11 == puVar2) - (uint)(puVar9 == puVar1);
      while ((puVar9 != puVar1 && (iVar7 == 0))) {
        if (((short)*puVar9 == 0x5c) || ((short)*puVar9 == 0x2f)) {
          bVar3 = 1;
        }
        else {
          bVar3 = 0;
        }
        if (((short)*puVar11 == 0x5c) || ((short)*puVar11 == 0x2f)) {
          iVar7 = 1;
        }
        else {
          iVar7 = 0;
        }
        if (iVar7 - (uint)bVar3 != 0) {
          return iVar7 - (uint)bVar3;
        }
        if (bVar3 == 0) {
          iVar7 = (uint)(ushort)*puVar9 - (uint)(ushort)*puVar11;
          if (iVar7 != 0) {
            return iVar7;
          }
          puVar9 = (uint *)((int)puVar9 + 2);
          puVar11 = (uint *)((int)puVar11 + 2);
        }
        else {
          do {
            puVar9 = (uint *)((int)puVar9 + 2);
            if (puVar9 == puVar1) break;
          } while ((*(short *)puVar9 == 0x5c) || (*(short *)puVar9 == 0x2f));
          do {
            puVar11 = (uint *)((int)puVar11 + 2);
            if (puVar11 == puVar2) break;
          } while ((*(short *)puVar11 == 0x5c) || (*(short *)puVar11 == 0x2f));
        }
        iVar7 = (uint)(puVar11 == puVar2) - (uint)(puVar9 == puVar1);
      }
    }
  }
  return iVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001c2d0 @ 1001c2d0