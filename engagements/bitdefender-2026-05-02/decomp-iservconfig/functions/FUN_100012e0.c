void FUN_100012e0(void)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  uint local_bc;
  wchar_t *local_b8 [5];
  undefined4 local_a4;
  undefined4 local_a0;
  wchar_t *local_9c;
  undefined4 local_98;
  undefined4 local_94;
  wchar_t *local_90;
  undefined4 local_8c;
  undefined4 local_88;
  wchar_t *local_84;
  undefined4 local_80;
  undefined4 local_7c;
  wchar_t *local_78;
  undefined4 local_74;
  undefined4 local_70;
  wchar_t *local_6c;
  undefined4 local_68;
  undefined4 local_64;
  wchar_t *local_60;
  undefined4 local_5c;
  undefined4 local_58;
  wchar_t *local_54;
  undefined4 local_50;
  undefined4 local_4c;
  wchar_t *local_48;
  undefined4 local_44;
  undefined4 local_40;
  wchar_t *local_3c;
  undefined4 local_38;
  undefined4 local_34;
  wchar_t *local_30;
  undefined4 local_2c;
  undefined4 local_28;
  wchar_t *local_24;
  undefined4 local_20;
  undefined4 local_1c;
  wchar_t *local_18;
  undefined4 local_14;
  undefined4 local_10;
  wchar_t *local_c;
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_bc = 0xf;
  local_b8[0] = (wchar_t *)0x0;
  local_b8[1] = L"<#ProductName#>";
  local_b8[2] = (wchar_t *)0x16;
  local_b8[3] = (wchar_t *)0x1;
  local_b8[4] = L"<#ProductNameColored#>";
  local_a4 = 0x13;
  local_a0 = 2;
  local_9c = L"<#FullProductName#>";
  local_98 = 0xf;
  local_94 = 3;
  local_90 = L"<#ProductType#>";
  local_8c = 0xf;
  local_88 = 8;
  local_84 = L"<#CompanyName#>";
  local_80 = 0x12;
  local_7c = 9;
  local_78 = L"<#CompanyAddress#>";
  local_74 = 0xd;
  local_70 = 10;
  local_6c = L"<#FaxNumber#>";
  local_68 = 0xf;
  local_64 = 0xb;
  local_60 = L"<#PhoneNumber#>";
  local_5c = 0x13;
  local_58 = 0xc;
  local_54 = L"<#ProductNameHtml#>";
  local_50 = 0x12;
  local_4c = 0xd;
  local_48 = L"<#ProductLinkBuy#>";
  local_44 = 0x16;
  local_40 = 0xe;
  local_3c = L"<#ProductLinkSupport#>";
  local_38 = 0x12;
  local_34 = 0xf;
  local_30 = L"<#ProductWebPage#>";
  local_2c = 0x12;
  local_28 = 0x10;
  local_24 = L"<#ProductFaqPage#>";
  local_20 = 0x16;
  local_1c = 0x11;
  local_18 = L"<#ProductWhyRegister#>";
  local_14 = 0x17;
  local_10 = 0x12;
  local_c = L"<#FullProductNameHtml#>";
  puVar2 = (uint *)operator_new(0xb4);
  _DAT_1006b654 = puVar2 + 0x2d;
  puVar3 = &local_bc;
  DAT_1006b650 = puVar2;
  DAT_1006b64c = puVar2;
  do {
    uVar1 = *puVar3;
    puVar3 = puVar3 + 3;
    *DAT_1006b650 = uVar1;
    DAT_1006b650[1] = *(uint *)(((int)local_b8 - (int)puVar2) + (int)DAT_1006b650);
    DAT_1006b650[2] = *(uint *)((int)local_b8 + (4 - (int)puVar2) + (int)DAT_1006b650);
    DAT_1006b650 = DAT_1006b650 + 3;
  } while (puVar3 != &local_8);
  _atexit((_func_4879 *)&LAB_10050f10);
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100014e0 @ 100014e0