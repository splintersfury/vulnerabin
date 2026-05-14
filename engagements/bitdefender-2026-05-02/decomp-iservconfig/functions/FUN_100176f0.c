undefined4 __thiscall FUN_100176f0(void *this,undefined1 param_1)

{
  void *this_00;
  undefined1 *puVar1;
  undefined4 uVar2;
  char *pcVar3;
  char local_1c [8];
  undefined8 local_14;
  undefined4 local_c;
  undefined4 local_8;
  
  if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
                    /* WARNING: Load size is inaccurate */
    pcVar3 = *this;
  }
  else {
    pcVar3 = *(char **)(*(int *)((int)this + 8) + -4);
    if (*pcVar3 == '\x02') {
      this_00 = *(void **)(pcVar3 + 8);
      puVar1 = *(undefined1 **)((int)this_00 + 4);
      if (puVar1 != *(undefined1 **)((int)this_00 + 8)) {
        local_c = CONCAT31(local_c._1_3_,param_1);
        *(undefined4 *)(puVar1 + 8) = local_c;
        *puVar1 = 4;
        *(undefined4 *)(puVar1 + 0xc) = local_8;
        *(int *)((int)this_00 + 4) = *(int *)((int)this_00 + 4) + 0x10;
        return CONCAT31(local_c._1_3_,1);
      }
      puVar1 = FUN_1001b440(this_00,puVar1,&param_1);
      return CONCAT31((int3)((uint)puVar1 >> 8),1);
    }
    pcVar3 = *(char **)((int)this + 0x10);
  }
  local_c = CONCAT31(local_c._1_3_,param_1);
  local_1c[0] = *pcVar3;
  *pcVar3 = '\x04';
  local_14 = *(undefined8 *)(pcVar3 + 8);
  *(undefined4 *)(pcVar3 + 0xc) = local_8;
  *(undefined4 *)(pcVar3 + 8) = local_c;
  uVar2 = FUN_1000e760(local_1c);
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_100177a0 @ 100177a0