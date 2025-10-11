#ifndef __CUSTOM31_INC
#define __CUSTOM31_INC

[Differentiable]
public float3 c31_deform(uniform float3 xyz) {
  return float3(
    sin(xyz.x) * sin(xyz.z),
    xyz.y,
    sin(xyz.x) * sin(xyz.z)
  );
}

public float3x3 c31_deform_jacobian(uniform float3 xyz, uniform float3 n) {
  DifferentialPair<float3> dp_x = diffPair(xyz, float3(1, 0, 0));
  DifferentialPair<float3> dp_y = diffPair(xyz, float3(0, 1, 0));
  DifferentialPair<float3> dp_z = diffPair(xyz, float3(0, 0, 1));

  DifferentialPair<float3> dp_x_out = fwd_diff(c31_deform)(dp_x);
  DifferentialPair<float3> dp_y_out = fwd_diff(c31_deform)(dp_y);
  DifferentialPair<float3> dp_z_out = fwd_diff(c31_deform)(dp_z);

  return float3x3(dp_x_out.d, dp_y_out.d, dp_z_out.d);
}

#endif  // __CUSTOM31_INC

