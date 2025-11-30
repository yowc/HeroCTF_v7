; ModuleID = 'src/valid_pass.c'
source_filename = "src/valid_pass.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.pos_s = type { i8, i8 }

@g_map = dso_local local_unnamed_addr global [10 x [10 x i8]] zeroinitializer, align 16
@.str.2 = private unnamed_addr constant [5 x i8] c"LEFT\00", align 1
@.str.3 = private unnamed_addr constant [6 x i8] c"RIGHT\00", align 1
@.str.4 = private unnamed_addr constant [3 x i8] c"UP\00", align 1
@.str.5 = private unnamed_addr constant [5 x i8] c"DOWN\00", align 1
@.str.6 = private unnamed_addr constant [4 x i8] c"%s \00", align 1
@switch.table.main.rel = private unnamed_addr constant [4 x i32] [i32 trunc (i64 sub (i64 ptrtoint (ptr @.str.2 to i64), i64 ptrtoint (ptr @switch.table.main.rel to i64)) to i32), i32 trunc (i64 sub (i64 ptrtoint (ptr @.str.3 to i64), i64 ptrtoint (ptr @switch.table.main.rel to i64)) to i32), i32 trunc (i64 sub (i64 ptrtoint (ptr @.str.4 to i64), i64 ptrtoint (ptr @switch.table.main.rel to i64)) to i32), i32 trunc (i64 sub (i64 ptrtoint (ptr @.str.5 to i64), i64 ptrtoint (ptr @switch.table.main.rel to i64)) to i32)], align 4

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong memory(read, argmem: readwrite, inaccessiblemem: none) uwtable
define dso_local void @chose_direction(ptr noundef writeonly captures(none) %0, ptr noundef captures(none) %1, ptr noundef captures(none) %2, i16 %3) local_unnamed_addr #0 {
  %5 = lshr i16 %3, 8
  %6 = zext nneg i16 %5 to i32
  %7 = getelementptr inbounds nuw i8, ptr %2, i64 1
  %8 = and i16 %3, 255
  %9 = zext nneg i16 %8 to i32
  %10 = trunc i16 %3 to i8
  %11 = getelementptr inbounds nuw i8, ptr %2, i64 1
  %12 = getelementptr inbounds nuw i8, ptr %2, i64 1
  %13 = getelementptr inbounds nuw i8, ptr %2, i64 1
  br label %14

14:                                               ; preds = %86, %4
  %15 = load i8, ptr %2, align 1, !tbaa !5
  %16 = icmp eq i8 %15, %10
  br i1 %16, label %17, label %21

17:                                               ; preds = %14
  %18 = load i8, ptr %7, align 1, !tbaa !9
  %19 = zext i8 %18 to i16
  %20 = icmp eq i16 %5, %19
  br i1 %20, label %93, label %21

21:                                               ; preds = %14, %17
  %22 = zext i8 %15 to i32
  %23 = icmp samesign ugt i32 %22, %9
  br i1 %23, label %24, label %38

24:                                               ; preds = %21
  %25 = add nsw i32 %22, -1
  %26 = zext nneg i32 %25 to i64
  %27 = load i8, ptr %11, align 1, !tbaa !9
  %28 = zext i8 %27 to i64
  %29 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %26, i64 %28
  %30 = load i8, ptr %29, align 1, !tbaa !10
  %31 = icmp eq i8 %30, 79
  br i1 %31, label %38, label %32

32:                                               ; preds = %24
  %33 = trunc nuw i32 %25 to i8
  store i8 %33, ptr %2, align 1, !tbaa !5
  %34 = load i8, ptr %1, align 1, !tbaa !10
  %35 = add i8 %34, 1
  store i8 %35, ptr %1, align 1, !tbaa !10
  %36 = zext i8 %34 to i64
  %37 = getelementptr inbounds nuw i32, ptr %0, i64 %36
  store i32 0, ptr %37, align 4, !tbaa !11
  br label %38

38:                                               ; preds = %24, %32, %21
  %39 = load i8, ptr %2, align 1, !tbaa !5
  %40 = zext i8 %39 to i32
  %41 = icmp samesign ult i32 %40, %9
  br i1 %41, label %42, label %56

42:                                               ; preds = %38
  %43 = add nuw nsw i32 %40, 1
  %44 = zext nneg i32 %43 to i64
  %45 = load i8, ptr %12, align 1, !tbaa !9
  %46 = zext i8 %45 to i64
  %47 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %44, i64 %46
  %48 = load i8, ptr %47, align 1, !tbaa !10
  %49 = icmp eq i8 %48, 79
  br i1 %49, label %50, label %56

50:                                               ; preds = %42
  %51 = trunc nuw i32 %43 to i8
  store i8 %51, ptr %2, align 1, !tbaa !5
  %52 = load i8, ptr %1, align 1, !tbaa !10
  %53 = add i8 %52, 1
  store i8 %53, ptr %1, align 1, !tbaa !10
  %54 = zext i8 %52 to i64
  %55 = getelementptr inbounds nuw i32, ptr %0, i64 %54
  store i32 1, ptr %55, align 4, !tbaa !11
  br label %56

56:                                               ; preds = %42, %50, %38
  %57 = load i8, ptr %13, align 1, !tbaa !9
  %58 = zext i8 %57 to i32
  %59 = icmp samesign ugt i32 %58, %6
  br i1 %59, label %60, label %74

60:                                               ; preds = %56
  %61 = load i8, ptr %2, align 1, !tbaa !5
  %62 = zext i8 %61 to i64
  %63 = add nsw i32 %58, -1
  %64 = zext nneg i32 %63 to i64
  %65 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %62, i64 %64
  %66 = load i8, ptr %65, align 1, !tbaa !10
  %67 = icmp eq i8 %66, 79
  br i1 %67, label %68, label %74

68:                                               ; preds = %60
  %69 = trunc nuw i32 %63 to i8
  store i8 %69, ptr %13, align 1, !tbaa !9
  %70 = load i8, ptr %1, align 1, !tbaa !10
  %71 = add i8 %70, 1
  store i8 %71, ptr %1, align 1, !tbaa !10
  %72 = zext i8 %70 to i64
  %73 = getelementptr inbounds nuw i32, ptr %0, i64 %72
  store i32 2, ptr %73, align 4, !tbaa !11
  br label %74

74:                                               ; preds = %60, %68, %56
  %75 = load i8, ptr %13, align 1, !tbaa !9
  %76 = zext i8 %75 to i32
  %77 = icmp samesign ult i32 %76, %6
  br i1 %77, label %78, label %86

78:                                               ; preds = %74
  %79 = load i8, ptr %2, align 1, !tbaa !5
  %80 = zext i8 %79 to i64
  %81 = add nuw nsw i32 %76, 1
  %82 = zext nneg i32 %81 to i64
  %83 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %80, i64 %82
  %84 = load i8, ptr %83, align 1, !tbaa !10
  %85 = icmp eq i8 %84, 79
  br i1 %85, label %87, label %86

86:                                               ; preds = %78, %87, %74
  br label %14, !llvm.loop !13

87:                                               ; preds = %78
  %88 = trunc nuw i32 %81 to i8
  store i8 %88, ptr %13, align 1, !tbaa !9
  %89 = load i8, ptr %1, align 1, !tbaa !10
  %90 = add i8 %89, 1
  store i8 %90, ptr %1, align 1, !tbaa !10
  %91 = zext i8 %89 to i64
  %92 = getelementptr inbounds nuw i32, ptr %0, i64 %91
  store i32 3, ptr %92, align 4, !tbaa !11
  br label %86

93:                                               ; preds = %17
  ret void
}

; Function Attrs: noinline nounwind sspstrong uwtable
define dso_local void @place_entity(ptr noundef captures(none) initializes((0, 2)) %0, i8 noundef zeroext %1, ptr noundef captures(none) %2, ptr noundef captures(none) %3) local_unnamed_addr #1 {
  %5 = getelementptr inbounds nuw i8, ptr %0, i64 1
  br label %6

6:                                                ; preds = %4, %29
  %7 = phi i32 [ 0, %4 ], [ %30, %29 ]
  %8 = tail call i32 @rand() #10
  %9 = srem i32 %8, 10
  %10 = trunc nsw i32 %9 to i8
  %11 = tail call i32 @rand() #10
  %12 = srem i32 %11, 10
  %13 = trunc nsw i32 %12 to i8
  store i8 %10, ptr %0, align 1, !tbaa !10
  store i8 %13, ptr %5, align 1, !tbaa !10
  %14 = load i8, ptr %3, align 1, !tbaa !10
  %15 = icmp eq i8 %14, 0
  br i1 %15, label %32, label %19

16:                                               ; preds = %25
  %17 = add nuw i8 %20, 1
  %18 = icmp eq i8 %17, %14
  br i1 %18, label %29, label %19, !llvm.loop !16

19:                                               ; preds = %6, %16
  %20 = phi i8 [ %17, %16 ], [ 0, %6 ]
  %21 = zext i8 %20 to i64
  %22 = getelementptr inbounds nuw %struct.pos_s, ptr %2, i64 %21
  %23 = load i8, ptr %22, align 1, !tbaa !5
  %24 = icmp eq i8 %23, %10
  br i1 %24, label %25, label %29

25:                                               ; preds = %19
  %26 = getelementptr inbounds nuw i8, ptr %22, i64 1
  %27 = load i8, ptr %26, align 1, !tbaa !9
  %28 = icmp eq i8 %27, %13
  br i1 %28, label %16, label %29

29:                                               ; preds = %19, %25, %16
  %30 = phi i32 [ %7, %16 ], [ 1, %25 ], [ 1, %19 ]
  %31 = icmp eq i32 %30, 0
  br i1 %31, label %6, label %32, !llvm.loop !17

32:                                               ; preds = %29, %6
  %33 = load i8, ptr %0, align 1, !tbaa !5
  %34 = zext i8 %33 to i64
  %35 = getelementptr inbounds nuw i8, ptr %0, i64 1
  %36 = load i8, ptr %35, align 1, !tbaa !9
  %37 = zext i8 %36 to i64
  %38 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %34, i64 %37
  store i8 %1, ptr %38, align 1, !tbaa !10
  %39 = load i8, ptr %3, align 1, !tbaa !10
  %40 = add i8 %39, 1
  store i8 %40, ptr %3, align 1, !tbaa !10
  %41 = zext i8 %39 to i64
  %42 = getelementptr inbounds nuw %struct.pos_s, ptr %2, i64 %41
  %43 = load i16, ptr %0, align 1
  store i16 %43, ptr %42, align 1
  ret void
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg, ptr captures(none)) #2

; Function Attrs: nounwind
declare i32 @rand() local_unnamed_addr #3

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr captures(none)) #2

; Function Attrs: nofree noinline norecurse nosync nounwind sspstrong memory(read, argmem: readwrite, inaccessiblemem: none) uwtable
define dso_local void @get_direction(ptr noundef writeonly captures(none) %0, ptr noundef captures(none) %1, i16 %2, i16 %3, i16 %4) local_unnamed_addr #0 {
  %6 = alloca %struct.pos_s, align 2
  call void @llvm.lifetime.start.p0(i64 2, ptr nonnull %6) #10
  store i16 %2, ptr %6, align 2
  call void @chose_direction(ptr noundef %0, ptr noundef %1, ptr noundef nonnull %6, i16 %4)
  call void @chose_direction(ptr noundef %0, ptr noundef %1, ptr noundef nonnull %6, i16 %3)
  call void @llvm.lifetime.end.p0(i64 2, ptr nonnull %6) #10
  ret void
}

; Function Attrs: nofree nounwind sspstrong uwtable
define dso_local void @show_map() local_unnamed_addr #4 {
  br label %1

1:                                                ; preds = %0, %4
  %2 = phi i64 [ 0, %0 ], [ %6, %4 ]
  br label %8

3:                                                ; preds = %4
  ret void

4:                                                ; preds = %8
  %5 = tail call i32 @putchar(i32 10)
  %6 = add nuw nsw i64 %2, 1
  %7 = icmp eq i64 %6, 10
  br i1 %7, label %3, label %1, !llvm.loop !18

8:                                                ; preds = %1, %8
  %9 = phi i64 [ 0, %1 ], [ %14, %8 ]
  %10 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %9, i64 %2
  %11 = load i8, ptr %10, align 1, !tbaa !10
  %12 = sext i8 %11 to i32
  %13 = tail call i32 @putchar(i32 %12)
  %14 = add nuw nsw i64 %9, 1
  %15 = icmp eq i64 %14, 10
  br i1 %15, label %4, label %8, !llvm.loop !19
}

; Function Attrs: nofree nounwind
declare noundef i32 @printf(ptr noundef readonly captures(none), ...) local_unnamed_addr #5

; Function Attrs: nounwind sspstrong uwtable
define dso_local noundef i32 @main() local_unnamed_addr #6 {
  %1 = alloca [10 x %struct.pos_s], align 16
  %2 = alloca i8, align 1
  %3 = alloca %struct.pos_s, align 2
  %4 = alloca %struct.pos_s, align 2
  %5 = alloca %struct.pos_s, align 2
  %6 = alloca %struct.pos_s, align 2
  %7 = alloca [100 x i32], align 16
  %8 = alloca i8, align 1
  tail call void asm sideeffect "nop", "~{dirflag},~{fpsr},~{flags}"() #10, !srcloc !20
  call void @llvm.lifetime.start.p0(i64 20, ptr nonnull %1) #10
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(20) %1, i8 0, i64 20, i1 false)
  call void @llvm.lifetime.start.p0(i64 1, ptr nonnull %2) #10
  store i8 0, ptr %2, align 1, !tbaa !10
  call void @llvm.lifetime.start.p0(i64 2, ptr nonnull %3) #10
  store i16 0, ptr %3, align 2
  call void @llvm.lifetime.start.p0(i64 2, ptr nonnull %4) #10
  store i16 0, ptr %4, align 2
  call void @llvm.lifetime.start.p0(i64 2, ptr nonnull %5) #10
  store i16 0, ptr %5, align 2
  call void @llvm.lifetime.start.p0(i64 2, ptr nonnull %6) #10
  store i16 0, ptr %6, align 2
  call void @llvm.lifetime.start.p0(i64 400, ptr nonnull %7) #10
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(400) %7, i8 0, i64 400, i1 false)
  call void @llvm.lifetime.start.p0(i64 1, ptr nonnull %8) #10
  store i8 0, ptr %8, align 1, !tbaa !10
  %9 = tail call i64 @time(ptr noundef null) #10
  %10 = trunc i64 %9 to i32
  tail call void @srand(i32 noundef %10) #10
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(100) @g_map, i8 77, i64 100, i1 false)
  call void @place_entity(ptr noundef nonnull %3, i8 noundef zeroext 72, ptr noundef nonnull %1, ptr noundef nonnull %2)
  call void @place_entity(ptr noundef nonnull %4, i8 noundef zeroext 69, ptr noundef nonnull %1, ptr noundef nonnull %2)
  call void @place_entity(ptr noundef nonnull %5, i8 noundef zeroext 82, ptr noundef nonnull %1, ptr noundef nonnull %2)
  call void @place_entity(ptr noundef nonnull %6, i8 noundef zeroext 79, ptr noundef nonnull %1, ptr noundef nonnull %2)
  br label %11

11:                                               ; preds = %13, %0
  %12 = phi i64 [ 0, %0 ], [ %15, %13 ]
  br label %17

13:                                               ; preds = %17
  %14 = tail call i32 @putchar(i32 10)
  %15 = add nuw nsw i64 %12, 1
  %16 = icmp eq i64 %15, 10
  br i1 %16, label %25, label %11, !llvm.loop !18

17:                                               ; preds = %17, %11
  %18 = phi i64 [ 0, %11 ], [ %23, %17 ]
  %19 = getelementptr inbounds nuw [10 x [10 x i8]], ptr @g_map, i64 0, i64 %18, i64 %12
  %20 = load i8, ptr %19, align 1, !tbaa !10
  %21 = sext i8 %20 to i32
  %22 = tail call i32 @putchar(i32 %21)
  %23 = add nuw nsw i64 %18, 1
  %24 = icmp eq i64 %23, 10
  br i1 %24, label %13, label %17, !llvm.loop !19

25:                                               ; preds = %13
  %26 = load i16, ptr %3, align 2
  %27 = load i16, ptr %4, align 2
  %28 = load i16, ptr %5, align 2
  call void @get_direction(ptr noundef nonnull %7, ptr noundef nonnull %8, i16 %26, i16 %27, i16 %28)
  %29 = load i8, ptr %8, align 1, !tbaa !10
  %30 = icmp eq i8 %29, 0
  br i1 %30, label %33, label %31

31:                                               ; preds = %25
  %32 = zext i8 %29 to i64
  br label %35

33:                                               ; preds = %44, %25
  %34 = tail call i32 @putchar(i32 10)
  call void @llvm.lifetime.end.p0(i64 1, ptr nonnull %8) #10
  call void @llvm.lifetime.end.p0(i64 400, ptr nonnull %7) #10
  call void @llvm.lifetime.end.p0(i64 2, ptr nonnull %6) #10
  call void @llvm.lifetime.end.p0(i64 2, ptr nonnull %5) #10
  call void @llvm.lifetime.end.p0(i64 2, ptr nonnull %4) #10
  call void @llvm.lifetime.end.p0(i64 2, ptr nonnull %3) #10
  call void @llvm.lifetime.end.p0(i64 1, ptr nonnull %2) #10
  call void @llvm.lifetime.end.p0(i64 20, ptr nonnull %1) #10
  ret i32 0

35:                                               ; preds = %31, %44
  %36 = phi i64 [ 0, %31 ], [ %47, %44 ]
  %37 = getelementptr inbounds nuw [100 x i32], ptr %7, i64 0, i64 %36
  %38 = load i32, ptr %37, align 4, !tbaa !11
  %39 = icmp ult i32 %38, 4
  br i1 %39, label %40, label %44

40:                                               ; preds = %35
  %41 = zext nneg i32 %38 to i64
  %42 = shl i64 %41, 2
  %43 = call ptr @llvm.load.relative.i64(ptr @switch.table.main.rel, i64 %42)
  br label %44

44:                                               ; preds = %40, %35
  %45 = phi ptr [ null, %35 ], [ %43, %40 ]
  %46 = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str.6, ptr noundef %45)
  %47 = add nuw nsw i64 %36, 1
  %48 = icmp eq i64 %47, %32
  br i1 %48, label %33, label %35, !llvm.loop !21
}

; Function Attrs: mustprogress nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr writeonly captures(none), i8, i64, i1 immarg) #7

; Function Attrs: nounwind
declare void @srand(i32 noundef) local_unnamed_addr #3

; Function Attrs: nounwind
declare i64 @time(ptr noundef) local_unnamed_addr #3

; Function Attrs: nofree nounwind
declare noundef i32 @putchar(i32 noundef) local_unnamed_addr #8

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: read)
declare ptr @llvm.load.relative.i64(ptr, i64) #9

attributes #0 = { nofree noinline norecurse nosync nounwind sspstrong memory(read, argmem: readwrite, inaccessiblemem: none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { noinline nounwind sspstrong uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nofree nounwind sspstrong uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nofree nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #6 = { nounwind sspstrong uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #7 = { mustprogress nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #8 = { nofree nounwind }
attributes #9 = { nocallback nofree nosync nounwind willreturn memory(argmem: read) }
attributes #10 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"clang version 21.1.5"}
!5 = !{!6, !7, i64 0}
!6 = !{!"pos_s", !7, i64 0, !7, i64 1}
!7 = !{!"omnipotent char", !8, i64 0}
!8 = !{!"Simple C/C++ TBAA"}
!9 = !{!6, !7, i64 1}
!10 = !{!7, !7, i64 0}
!11 = !{!12, !12, i64 0}
!12 = !{!"int", !7, i64 0}
!13 = distinct !{!13, !14, !15}
!14 = !{!"llvm.loop.mustprogress"}
!15 = !{!"llvm.loop.unroll.disable"}
!16 = distinct !{!16, !14, !15}
!17 = distinct !{!17, !14, !15}
!18 = distinct !{!18, !14, !15}
!19 = distinct !{!19, !14, !15}
!20 = !{i64 2711}
!21 = distinct !{!21, !14, !15}
