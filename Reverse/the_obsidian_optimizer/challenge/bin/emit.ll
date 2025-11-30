; ModuleID = 'src/valid_pass.c'
source_filename = "src/valid_pass.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@g_fp1 = dso_local global ptr null, align 8
@g_fp2 = dso_local global ptr null, align 8
@g_fp3 = dso_local global ptr null, align 8
@g_rv = dso_local global i64 0, align 8
@g_tbs = dso_local global i64 0, align 8
@g_tb = dso_local global ptr null, align 8

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local ptr @swap_me(i64 noundef %0, i64 noundef %1, i64 noundef %2, i64 noundef %3) #0 {
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  %8 = alloca i64, align 8
  store i64 %0, ptr %5, align 8
  store i64 %1, ptr %6, align 8
  store i64 %2, ptr %7, align 8
  store i64 %3, ptr %8, align 8
  ret ptr null
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @check(ptr noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  store ptr %0, ptr %3, align 8
  store i32 0, ptr %4, align 4
  br label %8

8:                                                ; preds = %17, %1
  %9 = load i32, ptr %4, align 4
  %10 = icmp slt i32 %9, 42
  br i1 %10, label %11, label %20

11:                                               ; preds = %8
  %12 = load i32, ptr %4, align 4
  %13 = icmp eq i32 %12, 41
  br i1 %13, label %14, label %16

14:                                               ; preds = %11
  %15 = call ptr @swap_me(i64 noundef 1, i64 noundef 2, i64 noundef 3, i64 noundef 4)
  store ptr %15, ptr @g_fp1, align 8
  br label %16

16:                                               ; preds = %14, %11
  br label %17

17:                                               ; preds = %16
  %18 = load i32, ptr %4, align 4
  %19 = add nsw i32 %18, 1
  store i32 %19, ptr %4, align 4
  br label %8, !llvm.loop !6

20:                                               ; preds = %8
  %21 = load ptr, ptr @g_fp1, align 8
  %22 = icmp ne ptr %21, null
  br i1 %22, label %24, label %23

23:                                               ; preds = %20
  store i32 1, ptr %2, align 4
  br label %104

24:                                               ; preds = %20
  store i64 0, ptr %5, align 8
  br label %25

25:                                               ; preds = %35, %24
  %26 = load i64, ptr %5, align 8
  %27 = icmp slt i64 %26, 4919
  br i1 %27, label %28, label %38

28:                                               ; preds = %25
  %29 = load i64, ptr %5, align 8
  %30 = icmp eq i64 %29, -1
  br i1 %30, label %31, label %34

31:                                               ; preds = %28
  %32 = load ptr, ptr @g_fp1, align 8
  %33 = call ptr %32(i64 noundef -1)
  store ptr %33, ptr @g_fp2, align 8
  br label %34

34:                                               ; preds = %31, %28
  br label %35

35:                                               ; preds = %34
  %36 = load i64, ptr %5, align 8
  %37 = add nsw i64 %36, 1
  store i64 %37, ptr %5, align 8
  br label %25, !llvm.loop !8

38:                                               ; preds = %25
  %39 = load ptr, ptr @g_fp2, align 8
  %40 = icmp ne ptr %39, null
  br i1 %40, label %42, label %41

41:                                               ; preds = %38
  store i32 2, ptr %2, align 4
  br label %104

42:                                               ; preds = %38
  store i64 4294967295, ptr %6, align 8
  br label %43

43:                                               ; preds = %58, %42
  %44 = load i64, ptr %6, align 8
  %45 = icmp ult i64 %44, 8589934591
  br i1 %45, label %46, label %61

46:                                               ; preds = %43
  %47 = load i64, ptr %6, align 8
  %48 = icmp eq i64 %47, 4277009103
  br i1 %48, label %49, label %57

49:                                               ; preds = %46
  %50 = load i64, ptr %6, align 8
  %51 = icmp ult i64 %50, -1
  br i1 %51, label %52, label %56

52:                                               ; preds = %49
  %53 = load ptr, ptr @g_fp2, align 8
  %54 = load i64, ptr %6, align 8
  %55 = call ptr %53(i64 noundef %54)
  store ptr %55, ptr @g_fp3, align 8
  br label %56

56:                                               ; preds = %52, %49
  br label %57

57:                                               ; preds = %56, %46
  br label %58

58:                                               ; preds = %57
  %59 = load i64, ptr %6, align 8
  %60 = add i64 %59, 1
  store i64 %60, ptr %6, align 8
  br label %43, !llvm.loop !9

61:                                               ; preds = %43
  %62 = load ptr, ptr @g_fp3, align 8
  %63 = icmp ne ptr %62, null
  br i1 %63, label %65, label %64

64:                                               ; preds = %61
  store i32 3, ptr %2, align 4
  br label %104

65:                                               ; preds = %61
  %66 = load ptr, ptr @g_fp3, align 8
  %67 = call ptr %66(i64 noundef 0)
  %68 = ptrtoint ptr %67 to i64
  store i64 %68, ptr @g_rv, align 8
  %69 = load ptr, ptr @g_fp3, align 8
  %70 = call ptr %69(i64 noundef 8)
  %71 = ptrtoint ptr %70 to i64
  store i64 %71, ptr @g_tbs, align 8
  %72 = load ptr, ptr @g_fp3, align 8
  %73 = call ptr %72(i64 noundef 16)
  store ptr %73, ptr @g_tb, align 8
  %74 = load i64, ptr @g_rv, align 8
  %75 = icmp eq i64 %74, 0
  br i1 %75, label %82, label %76

76:                                               ; preds = %65
  %77 = load i64, ptr @g_tbs, align 8
  %78 = icmp ne i64 %77, 3
  br i1 %78, label %82, label %79

79:                                               ; preds = %76
  %80 = load ptr, ptr @g_tb, align 8
  %81 = icmp eq ptr %80, null
  br i1 %81, label %82, label %83

82:                                               ; preds = %79, %76, %65
  store i32 4, ptr %2, align 4
  br label %104

83:                                               ; preds = %79
  store i64 0, ptr %7, align 8
  br label %84

84:                                               ; preds = %100, %83
  %85 = load i64, ptr %7, align 8
  %86 = load i64, ptr @g_tbs, align 8
  %87 = add i64 %86, 1
  %88 = icmp ult i64 %85, %87
  br i1 %88, label %89, label %103

89:                                               ; preds = %84
  %90 = load i64, ptr %7, align 8
  %91 = icmp eq i64 %90, 3
  br i1 %91, label %92, label %99

92:                                               ; preds = %89
  %93 = load ptr, ptr @g_tb, align 8
  %94 = load i64, ptr %7, align 8
  %95 = getelementptr inbounds nuw ptr, ptr %93, i64 %94
  %96 = load ptr, ptr %95, align 8
  %97 = load i64, ptr @g_rv, align 8
  %98 = call ptr %96(i64 noundef %97)
  br label %99

99:                                               ; preds = %92, %89
  br label %100

100:                                              ; preds = %99
  %101 = load i64, ptr %7, align 8
  %102 = add i64 %101, 1
  store i64 %102, ptr %7, align 8
  br label %84, !llvm.loop !10

103:                                              ; preds = %84
  store i32 11, ptr %2, align 4
  br label %104

104:                                              ; preds = %103, %82, %64, %41, %23
  %105 = load i32, ptr %2, align 4
  ret i32 %105
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 21.1.5"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = distinct !{!8, !7}
!9 = distinct !{!9, !7}
!10 = distinct !{!10, !7}
