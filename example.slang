#ifndef __EXAMPLE_INC
#define __EXAMPLE_INC

float3x3 inverse(float3x3 m) {
  float det =
    m._11 * (m._22 * m._33 - m._23 * m._32) -
    m._12 * (m._21 * m._33 - m._23 * m._31) +
    m._13 * (m._21 * m._32 - m._22 * m._31);

  if (abs(det) < 1e-6) {
    return float3x3(
        1,0,0,
        0,1,0,
        0,0,1);
  }

  float invDet = 1.0f / det;
  float3x3 inv;

  inv._11 = (m._22 * m._33 - m._23 * m._32) * invDet;
  inv._12 = (m._13 * m._32 - m._12 * m._33) * invDet;
  inv._13 = (m._12 * m._23 - m._13 * m._22) * invDet;
  inv._21 = (m._23 * m._31 - m._21 * m._33) * invDet;
  inv._22 = (m._11 * m._33 - m._13 * m._31) * invDet;
  inv._23 = (m._13 * m._21 - m._11 * m._23) * invDet;
  inv._31 = (m._21 * m._32 - m._22 * m._31) * invDet;
  inv._32 = (m._31 * m._12 - m._11 * m._32) * invDet;
  inv._33 = (m._11 * m._22 - m._12 * m._21) * invDet;

  return inv;
}

#define PI 3.14159265f

[Differentiable]
public float3 ex_deform(float3 xyz, no_diff float A, no_diff float k, no_diff float t) {
  float x = xyz.x;
  float y = xyz.y;
  float z = xyz.z;
  return float3(
    x + sin(y * k) * 0.1,
    y + sin(x * k * 4) * 0.5,
    (z + sin(x * y * k * PI + t) * A) * (1.0 + sin(y * k) * sin(x * k))
  );
}

// Deform a normal vector using the inverse transpose of the jacobian.
public void ex_deform_normal(float3 xyz, inout float3 normal, inout float3 tangent, float A, float k, float t) {
  // Compute jacobian using autodiff applied to basis vectors.
  DifferentialPair<float3> dp_x = diffPair(xyz, float3(1, 0, 0));
  DifferentialPair<float3> dp_y = diffPair(xyz, float3(0, 1, 0));
  DifferentialPair<float3> dp_z = diffPair(xyz, float3(0, 0, 1));

  DifferentialPair<float3> dp_x_out = fwd_diff(ex_deform)(dp_x, A, k, t);
  DifferentialPair<float3> dp_y_out = fwd_diff(ex_deform)(dp_y, A, k, t);
  DifferentialPair<float3> dp_z_out = fwd_diff(ex_deform)(dp_z, A, k, t);

  // Transform normal and tangent using jacobian
  float3x3 jacobian = float3x3(
    float3(dp_x_out.d.x, dp_y_out.d.x, dp_z_out.d.x),
    float3(dp_x_out.d.y, dp_y_out.d.y, dp_z_out.d.y),
    float3(dp_x_out.d.z, dp_y_out.d.z, dp_z_out.d.z)
  );
  float3x3 itjac = inverse(transpose(jacobian));
  normal = normalize(mul(itjac, normal));
  tangent = normalize(mul(jacobian, tangent));
}

#endif  // __EXAMPLE_INC

