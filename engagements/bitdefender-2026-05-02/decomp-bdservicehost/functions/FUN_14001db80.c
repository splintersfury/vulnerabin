void FUN_14001db80(longlong param_1,undefined8 param_2,char ****param_3,undefined8 param_4)

{
  byte bVar1;
  char cVar2;
  undefined1 uVar3;
  char ***pppcVar4;
  code *pcVar5;
  char *pcVar6;
  longlong lVar7;
  char *****pppppcVar8;
  longlong *plVar9;
  undefined1 auStack_168 [32];
  char *****local_148;
  char ***local_140;
  char ****local_138;
  longlong lStack_130;
  undefined8 local_128;
  longlong lStack_120;
  undefined8 local_118;
  longlong lStack_110;
  undefined8 local_100;
  longlong local_f8 [13];
  char local_90;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_168;
  lVar7 = *(longlong *)(param_1 + 0x38);
  bVar1 = *(byte *)(param_1 + 0xd8);
  if (lVar7 != 0) {
    FUN_140031e00((undefined1 (*) [16])local_f8,0,200);
    local_148 = &local_138;
    local_100 = 0;
    local_100 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar7,&local_138);
    plVar9 = (longlong *)(ulonglong)bVar1;
    pppppcVar8 = &local_138;
    FUN_14001e520(local_f8,param_3,(longlong *)pppppcVar8,plVar9);
    FUN_1400220b0(param_1,local_f8,(ulonglong *)pppppcVar8,plVar9);
    if (local_90 == '\0') {
      if (*(char *)param_3 == '\b') {
        FUN_14001de50((char *)&local_148,'\0');
        uVar3 = *(undefined1 *)param_3;
        *(undefined1 *)param_3 = local_148._0_1_;
        local_148 = (char *****)CONCAT71(local_148._1_7_,uVar3);
        pppcVar4 = param_3[1];
        param_3[1] = local_140;
        local_140 = pppcVar4;
        FUN_14001cf70((char *)&local_148);
      }
      FUN_14001e110((longlong)local_f8);
    }
    else {
      pcVar6 = (char *)FUN_14001de50((char *)&local_148,'\b');
      cVar2 = *(char *)param_3;
      *(char *)param_3 = *pcVar6;
      *pcVar6 = cVar2;
      pppcVar4 = param_3[1];
      param_3[1] = *(char ****)(pcVar6 + 8);
      *(char ****)(pcVar6 + 8) = pppcVar4;
      FUN_14001cf70(pcVar6);
      FUN_14001e110((longlong)local_f8);
    }
    goto LAB_14001dd65;
  }
  lStack_130 = 0;
  local_128 = 0;
  lStack_120 = 0;
  local_118 = 0;
  lStack_110 = (ulonglong)bVar1 << 8;
  local_138 = param_3;
  FUN_140023770(param_1,&local_138,param_3,param_4);
  if ((char)lStack_110 == '\0') {
    if (lStack_130 == 0) goto LAB_14001dd65;
    if (0xfff < (lStack_120 - lStack_130 & 0xfffffffffffffff8U)) {
      lVar7 = lStack_130 - *(longlong *)(lStack_130 + -8);
      goto joined_r0x00014001ddbe;
    }
  }
  else {
    pcVar6 = (char *)FUN_14001de50((char *)&local_148,'\b');
    cVar2 = *(char *)param_3;
    *(char *)param_3 = *pcVar6;
    *pcVar6 = cVar2;
    pppcVar4 = param_3[1];
    param_3[1] = *(char ****)(pcVar6 + 8);
    *(char ****)(pcVar6 + 8) = pppcVar4;
    FUN_14001cf70(pcVar6);
    if (lStack_130 == 0) goto LAB_14001dd65;
    if (0xfff < (lStack_120 - lStack_130 & 0xfffffffffffffff8U)) {
      lVar7 = lStack_130 - *(longlong *)(lStack_130 + -8);
joined_r0x00014001ddbe:
      if (0x1f < lVar7 - 8U) {
        FUN_140035d28();
        pcVar5 = (code *)swi(3);
        (*pcVar5)();
        return;
      }
    }
  }
  FUN_14002f180();
LAB_14001dd65:
  FUN_14002f160(local_28 ^ (ulonglong)auStack_168);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001ddd0 @ 14001ddd0