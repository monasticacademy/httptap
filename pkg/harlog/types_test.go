package harlog

import (
	"reflect"
	"testing"
	"time"
)

func TestTime_MarshalJSON(t *testing.T) {

	tz, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		t       Time
		want    string
		wantErr bool
	}{
		{
			name:    "plain",
			t:       Time(time.Date(2019, 10, 2, 12, 16, 30, 50, tz)),
			want:    `"2019-10-02T12:16:30+09:00"`,
			wantErr: false,
		},
		{
			name:    "zero value",
			t:       Time(time.Time{}),
			want:    `null`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.t.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("MarshalJSON() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestTime_UnmarshalJSON(t *testing.T) {

	// NOTE float64 - int64 の変換が生じるのでnsecレベルで誤差がでるのはしょうがない

	tz, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		data string
	}
	tests := []struct {
		name    string
		t       args
		want    Time
		wantErr bool
	}{
		{
			name: "plain",
			t: args{
				data: `"2019-10-02T12:16:31+09:00"`,
			},
			want:    Time(time.Date(2019, 10, 2, 12, 16, 31, 0, tz)),
			wantErr: false,
		},
		{
			name: "null",
			t: args{
				data: `null`,
			},
			want:    Time(time.Time{}),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v Time
			if err := v.UnmarshalJSON([]byte(tt.t.data)); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !time.Time(v).Equal(time.Time(tt.want)) {
				t.Errorf("UnmarshalJSON() got = %v, want %v", v, tt.want)
			}
		})
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		d       Duration
		want    string
		wantErr bool
	}{
		{
			name:    "plain",
			d:       Duration(10 * time.Millisecond),
			want:    "10",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.d.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("MarshalJSON() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    Duration
		wantErr bool
	}{
		{
			name: "plain",
			args: args{
				data: "10",
			},
			want:    Duration(10 * time.Millisecond),
			wantErr: false,
		},
		{
			name: "null",
			args: args{
				data: `null`,
			},
			want:    Duration(0),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v Duration
			if err := v.UnmarshalJSON([]byte(tt.args.data)); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if v != tt.want {
				t.Errorf("UnmarshalJSON() got = %v, want %v", v, tt.want)
			}
		})
	}
}
