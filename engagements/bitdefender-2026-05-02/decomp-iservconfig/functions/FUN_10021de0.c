void __thiscall
FUN_10021de0(void *this,undefined4 param_1,undefined4 param_2,void *param_3,void *param_4)

{
  char *pcVar1;
  code *pcVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined1 *puVar5;
  void *pvVar6;
  char local_34 [4];
  undefined1 *local_30;
  int *piStack_2c;
  undefined4 *local_28;
  undefined8 local_24;
  undefined1 local_15;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004feb5;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(undefined1 *)this = 0;
  *(undefined8 *)((int)this + 8) = 0;
  pvVar6 = param_3;
  if (param_3 != param_4) {
    do {
      if (((**(char **)((int)pvVar6 + 0x10) != '\x02') ||
          (puVar4 = *(undefined4 **)(*(char **)((int)pvVar6 + 0x10) + 8), pcVar1 = (char *)*puVar4,
          puVar4[1] - (int)pcVar1 >> 4 != 2)) || (*pcVar1 != '\x03')) {
        *(undefined1 *)this = 2;
        local_24 = 0;
        puVar4 = (undefined4 *)operator_new(0xc);
        local_24 = CONCAT44(puVar4,&local_15);
        local_8 = 4;
        *puVar4 = 0;
        puVar4[1] = 0;
        puVar4[2] = 0;
        uVar3 = ((int)param_4 - (int)param_3) / 0x18;
        if (uVar3 == 0) {
          *(undefined4 **)((int)this + 8) = puVar4;
        }
        else {
          if (0xfffffff < uVar3) {
            FUN_10017fa0();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
          puVar5 = (undefined1 *)FUN_1001ab40(uVar3);
          *puVar4 = puVar5;
          puVar4[1] = puVar5;
          puVar4[2] = puVar5 + uVar3 * 0x10;
          _local_30 = CONCAT44(puVar5,puVar5);
          local_8 = CONCAT31(local_8._1_3_,6);
          local_28 = puVar4;
          if (param_3 != param_4) {
            do {
              FUN_10022ff0(param_3,puVar5);
              puVar5 = puVar5 + 0x10;
              param_3 = (void *)((int)param_3 + 0x18);
              _local_30 = CONCAT44(puVar5,local_30);
            } while (param_3 != param_4);
          }
          puVar4[1] = puVar5;
          *(undefined4 **)((int)this + 8) = puVar4;
        }
        goto LAB_10021ecb;
      }
      pvVar6 = (void *)((int)pvVar6 + 0x18);
    } while (pvVar6 != param_4);
  }
  *(undefined1 *)this = 1;
  FUN_1000f600(&local_24,'\x01');
  *(int *)((int)this + 8) = (int)local_24;
  *(undefined4 *)((int)this + 0xc) = local_24._4_4_;
  if (param_3 != param_4) {
    do {
      FUN_10022ff0(param_3,local_34);
      local_8 = 3;
      FUN_10023a50(*(void **)((int)this + 8),(int *)&local_24,*(byte **)(*piStack_2c + 8),
                   (undefined1 *)(*piStack_2c + 0x10));
      local_8 = 0xffffffff;
      FUN_1000e760(local_34);
      param_3 = (void *)((int)param_3 + 0x18);
    } while (param_3 != param_4);
  }
LAB_10021ecb:
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10021fc0 @ 10021fc0