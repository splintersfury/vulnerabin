undefined4 * __thiscall FUN_100097f0(void *this,byte param_1)

{
  void *pvVar1;
  
  *(undefined ***)this = BDExportedObject<class_ProductInfo,1>::vftable;
  if (*(int **)((int)this + 0xc) != (int *)0x0) {
    (**(code **)(**(int **)((int)this + 0xc) + 0x4c))(1);
  }
  pvVar1 = *(void **)((int)this + 4);
  if (pvVar1 != (void *)0x0) {
    __Mtx_destroy_in_situ((int)pvVar1);
    FUN_1002e346(pvVar1);
  }
  *(undefined ***)this = IBDExportedObject::vftable;
  if ((param_1 & 1) != 0) {
    FUN_1002e346(this);
  }
  return (undefined4 *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009850 @ 10009850