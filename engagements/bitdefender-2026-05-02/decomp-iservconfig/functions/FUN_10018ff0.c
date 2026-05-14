int __thiscall FUN_10018ff0(void *this,char *param_1)

{
  char cVar1;
  char *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  void *this_00;
  char local_18 [8];
  undefined4 local_10;
  undefined4 local_c;
  
  if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
    local_18[0] = *param_1;
    FUN_1000f600(&local_10,local_18[0]);
                    /* WARNING: Load size is inaccurate */
    pcVar2 = *this;
    cVar1 = *pcVar2;
    *pcVar2 = local_18[0];
    uVar3 = *(undefined4 *)(pcVar2 + 0xc);
    uVar4 = *(undefined4 *)(pcVar2 + 8);
    *(undefined4 *)(pcVar2 + 0xc) = local_c;
    *(undefined4 *)(pcVar2 + 8) = local_10;
    local_18[0] = cVar1;
    local_10 = uVar4;
    local_c = uVar3;
    FUN_1000e760(local_18);
                    /* WARNING: Load size is inaccurate */
    return *this;
  }
  pcVar2 = *(char **)(*(int *)((int)this + 8) + -4);
  if (*pcVar2 == '\x02') {
    this_00 = *(void **)(pcVar2 + 8);
    pcVar2 = *(char **)((int)this_00 + 4);
    if (pcVar2 != *(char **)((int)this_00 + 8)) {
      cVar1 = *param_1;
      *pcVar2 = cVar1;
      FUN_1000f600(pcVar2 + 8,cVar1);
      *(int *)((int)this_00 + 4) = *(int *)((int)this_00 + 4) + 0x10;
      return *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + -4) + 8) + 4) + -0x10;
    }
    FUN_1001af40(this_00,pcVar2,param_1);
    return *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + -4) + 8) + 4) + -0x10;
  }
  local_18[0] = *param_1;
  FUN_1000f600(&local_10,local_18[0]);
  pcVar2 = *(char **)((int)this + 0x10);
  cVar1 = *pcVar2;
  *pcVar2 = local_18[0];
  uVar3 = *(undefined4 *)(pcVar2 + 0xc);
  uVar4 = *(undefined4 *)(pcVar2 + 8);
  *(undefined4 *)(pcVar2 + 0xc) = local_c;
  *(undefined4 *)(pcVar2 + 8) = local_10;
  local_18[0] = cVar1;
  local_10 = uVar4;
  local_c = uVar3;
  FUN_1000e760(local_18);
  return *(int *)((int)this + 0x10);
}


// FUNCTION_END

// FUNCTION_START: FUN_10019110 @ 10019110