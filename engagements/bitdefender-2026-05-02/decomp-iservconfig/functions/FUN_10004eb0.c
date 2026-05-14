undefined4 __fastcall FUN_10004eb0(undefined4 param_1)

{
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: seekpos @ 10004ec0

/* Library Function - Single Match
    protected: virtual class std::fpos<struct _Mbstatet> __thiscall std::basic_streambuf<char,struct
   std::char_traits<char> >::seekpos(class std::fpos<struct _Mbstatet>,int)
   
   Library: Visual Studio 2019 Release */

void __thiscall
std::basic_streambuf<char,struct_std::char_traits<char>_>::seekpos
          (undefined4 param_1,undefined4 *param_2)

{
  *param_2 = 0xffffffff;
  param_2[1] = 0xffffffff;
  param_2[2] = 0;
  param_2[3] = 0;
  *(undefined8 *)(param_2 + 4) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: seekoff @ 10004ef0

/* Library Function - Single Match
    protected: virtual class std::fpos<struct _Mbstatet> __thiscall std::basic_streambuf<char,struct
   std::char_traits<char> >::seekoff(__int64,int,int)
   
   Library: Visual Studio 2019 Release */

void __thiscall
std::basic_streambuf<char,struct_std::char_traits<char>_>::seekoff
          (basic_streambuf<char,struct_std::char_traits<char>_> *this,__int64 param_1,int param_2,
          int param_3)

{
  *(undefined4 *)param_1 = 0xffffffff;
  ((undefined4 *)param_1)[1] = 0xffffffff;
  ((undefined4 *)param_1)[2] = 0;
  ((undefined4 *)param_1)[3] = 0;
  *(undefined8 *)((undefined4 *)param_1 + 4) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004f20 @ 10004f20

/* WARNING: Removing unreachable block (ram,0x10004f6b) */
/* WARNING: Removing unreachable block (ram,0x10004f75) */