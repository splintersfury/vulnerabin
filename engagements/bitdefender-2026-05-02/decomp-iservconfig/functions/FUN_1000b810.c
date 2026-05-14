void __thiscall FUN_1000b810(void *this,undefined4 *param_1)

{
  int *piVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  uint *puVar5;
  uint *puVar6;
  undefined1 auStack_14 [4];
  undefined4 *local_10;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_14;
  piVar1 = (int *)((int)this + 0x10);
  local_10 = param_1;
  if (7 < *(uint *)((int)this + 0x14)) {
                    /* WARNING: Load size is inaccurate */
    this = *this;
  }
  puVar2 = (uint *)((int)this + *piVar1 * 2);
  puVar3 = FUN_1000b570((uint *)this,puVar2);
  puVar6 = puVar2;
  if (puVar3 == puVar2) {
LAB_1000b885:
    puVar4 = puVar6;
    puVar3 = puVar6;
    if (puVar6 != puVar2) {
      do {
        if ((short)*puVar3 == 0x3a) break;
        puVar3 = (uint *)((int)puVar3 + 2);
      } while (puVar3 != puVar2);
      puVar4 = puVar3;
      if ((puVar6 != puVar3) && (puVar2 = (uint *)((int)puVar3 + -2), puVar6 != puVar2)) {
        puVar5 = puVar3 + -1;
        if (*(short *)puVar2 == 0x2e) {
          if ((puVar6 != puVar5) || ((short)*puVar5 != 0x2e)) {
            puVar4 = puVar2;
          }
        }
        else {
          for (; (puVar4 = puVar3, puVar6 != puVar5 && (puVar4 = puVar5, (short)*puVar5 != 0x2e));
              puVar5 = (uint *)((int)puVar5 + -2)) {
          }
        }
      }
    }
  }
  else {
    do {
      if (((short)*puVar3 != 0x5c) && ((short)*puVar3 != 0x2f)) goto LAB_1000b870;
      puVar3 = (uint *)((int)puVar3 + 2);
      puVar4 = puVar2;
    } while (puVar3 != puVar2);
  }
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  FUN_10001d40(param_1,puVar6,(int)puVar4 - (int)puVar6 >> 1);
  FUN_1002e315(local_c ^ (uint)auStack_14);
  return;
LAB_1000b870:
  if (*(short *)((int)puVar6 + -2) == 0x5c) goto LAB_1000b885;
  if ((*(short *)((int)puVar6 + -2) == 0x2f) ||
     (puVar6 = (uint *)((int)puVar6 + -2), puVar3 == puVar6)) goto LAB_1000b885;
  goto LAB_1000b870;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b910 @ 1000b910