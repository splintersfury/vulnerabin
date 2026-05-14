void __thiscall FUN_10019110(void *this,uint *param_1)

{
  char *pcVar1;
  undefined1 *puVar2;
  undefined8 uVar3;
  uint *this_00;
  void *this_01;
  void *pvVar4;
  char local_40 [8];
  undefined8 local_38;
  char local_30 [8];
  undefined8 local_28;
  undefined1 local_1a;
  undefined1 local_19;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f4fd;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_38._4_4_ = param_1;
  if (*(int *)((int)this + 4) == *(int *)((int)this + 8)) {
    local_28 = 0;
    local_38 = 0;
    this_00 = (uint *)operator_new(0x18);
    local_38._0_4_ = &local_19;
    local_8 = 0;
    local_38._4_4_ = this_00;
    FUN_100056d0(this_00,param_1);
                    /* WARNING: Load size is inaccurate */
    pcVar1 = *this;
    local_30[0] = *pcVar1;
    *pcVar1 = '\x03';
    uVar3 = *(undefined8 *)(pcVar1 + 8);
    *(undefined4 *)(pcVar1 + 0xc) = local_28._4_4_;
    *(uint **)(pcVar1 + 8) = this_00;
    local_28 = uVar3;
    FUN_1000e760(local_30);
  }
  else {
    pcVar1 = *(char **)(*(int *)((int)this + 8) + -4);
    if (*pcVar1 == '\x02') {
      pvVar4 = *(void **)(pcVar1 + 8);
      puVar2 = *(undefined1 **)((int)pvVar4 + 4);
      if (puVar2 == *(undefined1 **)((int)pvVar4 + 8)) {
        FUN_1001b070(pvVar4,puVar2,param_1);
      }
      else {
        *(undefined8 *)(puVar2 + 8) = 0;
        *puVar2 = 3;
        local_28 = 0;
        this_01 = operator_new(0x18);
        local_28 = CONCAT44(this_01,&local_19);
        local_8 = 1;
        FUN_100056d0(this_01,local_38._4_4_);
        *(void **)(puVar2 + 8) = this_01;
        *(undefined4 *)(puVar2 + 0xc) = local_28._4_4_;
        *(int *)((int)pvVar4 + 4) = *(int *)((int)pvVar4 + 4) + 0x10;
      }
    }
    else {
      local_38 = 0;
      local_28 = 0;
      pvVar4 = operator_new(0x18);
      local_28 = CONCAT44(pvVar4,&local_1a);
      local_8 = 2;
      FUN_100056d0(pvVar4,param_1);
      pcVar1 = *(char **)((int)this + 0x10);
      local_40[0] = *pcVar1;
      *pcVar1 = '\x03';
      local_38._0_4_ = *(undefined1 **)(pcVar1 + 8);
      local_38._4_4_ = *(uint **)(pcVar1 + 0xc);
      *(void **)(pcVar1 + 8) = pvVar4;
      *(undefined4 *)(pcVar1 + 0xc) = local_28._4_4_;
      FUN_1000e760(local_40);
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100192b0 @ 100192b0